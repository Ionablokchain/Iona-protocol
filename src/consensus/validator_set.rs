//! Validator set management for IONA consensus.
//!
//! Defines the validator set (active validators + voting power), with:
//! - power queries, membership checks, quorum threshold
//! - deterministic proposer selection (round-robin)
//! - canonical hash for cross-node comparison
//! - diff/merge operations for live validator updates
//! - a thread-safe manager with an LRU proposer cache
//!
//! # Invariants
//!
//! - A [`ValidatorSet`] constructed via [`ValidatorSet::new`] is guaranteed
//!   non-empty, has positive power per validator, and no duplicate public
//!   keys.
//! - [`ValidatorSet::proposer_for`] panics on an empty set (documented);
//!   prefer [`ValidatorSet::try_proposer_for`] which returns `Option`.
//! - [`ValidatorSet::hash_hex`] is deterministic and order-independent: two
//!   sets with the same validators in a different order hash identically.
//!
//! # Concurrency
//!
//! [`ValidatorSetManager`] is `Clone + Send + Sync`. All internal state is
//! behind [`parking_lot::Mutex`], which does not poison on panic.

use crate::crypto::PublicKeyBytes;
use lru::LruCache;
use parking_lot::Mutex;
use prometheus::{Counter, CounterVec, Gauge};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::fmt;
use std::num::NonZeroUsize;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tracing::{info, trace, warn};

// ── Constants ─────────────────────────────────────────────────────────────

/// Panic message when `proposer_for` is called on an empty validator set.
const ERR_EMPTY_VALIDATOR_SET: &str = "ValidatorSet::proposer_for called with empty set";

/// Numerator for the quorum threshold (2/3).
const QUORUM_NUMERATOR: u64 = 2;

/// Denominator for the quorum threshold (3).
const QUORUM_DENOMINATOR: u64 = 3;

/// Default cache size for proposer lookups.
const DEFAULT_CACHE_SIZE: usize = 128;

/// Default cache TTL in seconds.
const DEFAULT_CACHE_TTL_SECS: u64 = 60;

// ── Configuration ─────────────────────────────────────────────────────────

/// Configuration for the validator set subsystem.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ValidatorSetConfig {
    /// Whether to enable caching of proposer lookups.
    pub enable_cache: bool,
    /// Maximum number of entries in the cache.
    pub cache_size: usize,
    /// Cache TTL in seconds.
    pub cache_ttl_secs: u64,
    /// Whether to validate validator sets on construction and update.
    pub validate_on_create: bool,
    /// Whether to enable metrics.
    pub enable_metrics: bool,
    /// Whether to log validator set changes.
    pub log_changes: bool,
}

impl Default for ValidatorSetConfig {
    fn default() -> Self {
        Self {
            enable_cache: true,
            cache_size: DEFAULT_CACHE_SIZE,
            cache_ttl_secs: DEFAULT_CACHE_TTL_SECS,
            validate_on_create: true,
            enable_metrics: true,
            log_changes: true,
        }
    }
}

impl ValidatorSetConfig {
    /// Validate the configuration.
    pub fn validate(&self) -> Result<(), String> {
        if self.cache_size == 0 {
            return Err("cache_size must be > 0".into());
        }
        if self.cache_ttl_secs == 0 {
            return Err("cache_ttl_secs must be > 0".into());
        }
        Ok(())
    }
}

// ── Metrics ──────────────────────────────────────────────────────────────

/// Prometheus metrics for the validator set subsystem.
///
/// # Registration
///
/// [`ValidatorSetMetrics::new`] registers with the **default** Prometheus
/// registry and can only be called once per process. Use
/// [`ValidatorSetMetrics::unregistered`] for a fail-free instance (that's
/// what `Default` does).
#[derive(Clone)]
pub struct ValidatorSetMetrics {
    pub validator_count: Gauge,
    pub total_power: Gauge,
    pub quorum_threshold: Gauge,
    pub proposer_checks: Counter,
    pub cache_hits: Counter,
    pub cache_misses: Counter,
    pub updates: CounterVec,
}

impl ValidatorSetMetrics {
    /// Register all metrics with the default Prometheus registry.
    pub fn new() -> Result<Self, prometheus::Error> {
        Ok(Self {
            validator_count: prometheus::register_gauge!(
                "iona_validator_count",
                "Number of active validators"
            )?,
            total_power: prometheus::register_gauge!(
                "iona_validator_total_power",
                "Total voting power"
            )?,
            quorum_threshold: prometheus::register_gauge!(
                "iona_validator_quorum_threshold",
                "Quorum threshold (2/3 + 1)"
            )?,
            proposer_checks: prometheus::register_counter!(
                "iona_validator_proposer_checks_total",
                "Total proposer lookups"
            )?,
            cache_hits: prometheus::register_counter!(
                "iona_validator_cache_hits_total",
                "Cache hits for proposer lookups"
            )?,
            cache_misses: prometheus::register_counter!(
                "iona_validator_cache_misses_total",
                "Cache misses for proposer lookups"
            )?,
            updates: prometheus::register_counter_vec!(
                "iona_validator_updates_total",
                "Validator set updates",
                &["type"]
            )?,
        })
    }

    /// Create an **unregistered** metrics bundle.
    ///
    /// Never fails, never registers. Suitable for tests or a custom registry.
    pub fn unregistered() -> Self {
        let mk_gauge = |name: &str, help: &str| {
            Gauge::new(name, help).expect("gauge construction is infallible")
        };
        let mk_counter = |name: &str, help: &str| {
            Counter::new(name, help).expect("counter construction is infallible")
        };
        Self {
            validator_count: mk_gauge("iona_validator_count", "Number of active validators"),
            total_power: mk_gauge("iona_validator_total_power", "Total voting power"),
            quorum_threshold: mk_gauge(
                "iona_validator_quorum_threshold",
                "Quorum threshold (2/3 + 1)",
            ),
            proposer_checks: mk_counter(
                "iona_validator_proposer_checks_total",
                "Total proposer lookups",
            ),
            cache_hits: mk_counter(
                "iona_validator_cache_hits_total",
                "Cache hits for proposer lookups",
            ),
            cache_misses: mk_counter(
                "iona_validator_cache_misses_total",
                "Cache misses for proposer lookups",
            ),
            updates: CounterVec::new(
                prometheus::Opts::new("iona_validator_updates_total", "Validator set updates"),
                &["type"],
            )
            .expect("counter vec construction is infallible"),
        }
    }

    pub fn set_validator_count(&self, count: usize) {
        self.validator_count.set(count as f64);
    }
    pub fn set_total_power(&self, power: u64) {
        self.total_power.set(power as f64);
    }
    pub fn set_quorum_threshold(&self, threshold: u64) {
        self.quorum_threshold.set(threshold as f64);
    }
    pub fn record_proposer_check(&self) {
        self.proposer_checks.inc();
    }
    pub fn record_cache_hit(&self) {
        self.cache_hits.inc();
    }
    pub fn record_cache_miss(&self) {
        self.cache_misses.inc();
    }
    pub fn record_update(&self, typ: &str) {
        self.updates.with_label_values(&[typ]).inc();
    }
}

impl Default for ValidatorSetMetrics {
    fn default() -> Self {
        Self::unregistered()
    }
}

// ── Types ────────────────────────────────────────────────────────────────

/// Voting power of a validator.
pub type VotingPower = u64;

/// A validator in the consensus set.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Validator {
    /// Public key of the validator.
    pub pk: PublicKeyBytes,
    /// Voting power (stake weight).
    pub power: VotingPower,
}

/// The active validator set.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ValidatorSet {
    /// Validators. Order is significant for round-robin proposer selection.
    pub vals: Vec<Validator>,
}

// ── Validation errors ────────────────────────────────────────────────────

/// Errors that can occur during validator set validation.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum ValidatorSetError {
    #[error("empty validator set")]
    EmptySet,

    #[error("duplicate public key: {0}")]
    DuplicatePublicKey(String),

    #[error("validator has zero power")]
    ZeroPower,

    #[error("validator set too large: {count} > max {max}")]
    TooLarge { count: usize, max: usize },

    /// Configuration error (invalid `ValidatorSetConfig`).
    #[error("configuration error: {0}")]
    Config(String),

    /// Validation failed during a manager operation.
    #[error("validation failed: {0}")]
    ValidationFailed(String),
}

pub type ValidatorSetResult<T> = Result<T, ValidatorSetError>;

// ── Implementation ──────────────────────────────────────────────────────

impl ValidatorSet {
    /// Create a new validator set with validation.
    ///
    /// Rejects empty sets, sets larger than `max_size`, sets with any
    /// zero-power validator, and sets with duplicate public keys.
    pub fn new(vals: Vec<Validator>, max_size: usize) -> ValidatorSetResult<Self> {
        if vals.is_empty() {
            return Err(ValidatorSetError::EmptySet);
        }
        if vals.len() > max_size {
            return Err(ValidatorSetError::TooLarge {
                count: vals.len(),
                max: max_size,
            });
        }

        let mut seen = HashSet::with_capacity(vals.len());
        for v in &vals {
            if v.power == 0 {
                return Err(ValidatorSetError::ZeroPower);
            }
            let key = hex::encode(&v.pk.0);
            if !seen.insert(key.clone()) {
                return Err(ValidatorSetError::DuplicatePublicKey(key));
            }
        }

        Ok(Self { vals })
    }

    /// Create from an existing set **without** validation.
    ///
    /// The caller asserts the set is well-formed (non-empty, no duplicate
    /// keys, no zero powers). Misuse will surface later as a panic in
    /// [`proposer_for`](Self::proposer_for).
    pub fn from_validated(vals: Vec<Validator>) -> Self {
        Self { vals }
    }

    /// Total voting power of all validators.
    ///
    /// Uses `saturating_add`, so an absurd total saturates at `u64::MAX`
    /// rather than wrapping.
    #[must_use]
    pub fn total_power(&self) -> VotingPower {
        self.vals
            .iter()
            .fold(0u64, |acc, v| acc.saturating_add(v.power))
    }

    /// Voting power of the validator with the given public key.
    ///
    /// Returns `0` if the key is not in the set.
    #[must_use]
    pub fn power_of(&self, pk: &PublicKeyBytes) -> VotingPower {
        self.vals
            .iter()
            .find(|v| &v.pk == pk)
            .map(|v| v.power)
            .unwrap_or(0)
    }

    /// Whether the given public key is in the set (with power > 0).
    #[must_use]
    pub fn contains(&self, pk: &PublicKeyBytes) -> bool {
        self.power_of(pk) > 0
    }

    /// Round-robin proposer for `(height, round)`.
    ///
    /// Index: `(height + round) mod vals.len()`.
    ///
    /// # Panics
    ///
    /// Panics if the validator set is empty. Prefer
    /// [`try_proposer_for`](Self::try_proposer_for) if you can't guarantee
    /// non-emptiness at the call site.
    #[must_use]
    pub fn proposer_for(&self, height: u64, round: u32) -> &Validator {
        self.try_proposer_for(height, round)
            .unwrap_or_else(|| panic!("{ERR_EMPTY_VALIDATOR_SET}"))
    }

    /// Round-robin proposer for `(height, round)`, or `None` if the set
    /// is empty.
    #[must_use]
    pub fn try_proposer_for(&self, height: u64, round: u32) -> Option<&Validator> {
        let n = self.vals.len();
        if n == 0 {
            return None;
        }
        let combined = height.wrapping_add(round as u64);
        let idx = (combined % (n as u64)) as usize;
        self.vals.get(idx)
    }

    /// Whether the set is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.vals.is_empty()
    }

    /// Number of validators.
    #[must_use]
    pub fn len(&self) -> usize {
        self.vals.len()
    }

    /// Iterator over the validators.
    pub fn iter(&self) -> std::slice::Iter<'_, Validator> {
        self.vals.iter()
    }

    /// Quorum threshold (`floor(total × 2 / 3) + 1`).
    ///
    /// Uses `saturating_mul` on the total, so an absurd total saturates
    /// rather than wrapping. For a well-formed set this equals the
    /// expected `2/3 + 1`.
    #[must_use]
    pub fn quorum_threshold(&self) -> VotingPower {
        let total = self.total_power();
        total
            .saturating_mul(QUORUM_NUMERATOR)
            .checked_div(QUORUM_DENOMINATOR)
            .unwrap_or(0)
            .saturating_add(1)
    }

    /// Deterministic, order-independent hash of the validator set.
    ///
    /// Encodes `(pk_bytes, power_le)` per validator, sorted by `pk`, then
    /// blake3's the result under a versioned prefix.
    #[must_use]
    pub fn hash_hex(&self) -> String {
        let mut sorted: Vec<&Validator> = self.vals.iter().collect();
        sorted.sort_by(|a, b| a.pk.0.cmp(&b.pk.0));

        let mut hasher = blake3::Hasher::new();
        hasher.update(b"iona/vset/v1:");
        hasher.update(&(sorted.len() as u64).to_le_bytes());
        for v in sorted {
            hasher.update(&v.pk.0);
            hasher.update(&v.power.to_le_bytes());
        }
        hasher.finalize().to_hex().to_string()
    }

    /// Difference between two validator sets.
    ///
    /// Returns `(added, removed, power_changed)`:
    /// - `added` — validators in `other` not in `self`
    /// - `removed` — validators in `self` not in `other`
    /// - `power_changed` — validators in both with different power (returns
    ///   the `other` version)
    #[must_use]
    pub fn diff(&self, other: &ValidatorSet) -> (Vec<Validator>, Vec<Validator>, Vec<Validator>) {
        let self_map: HashMap<&PublicKeyBytes, &Validator> =
            self.vals.iter().map(|v| (&v.pk, v)).collect();

        let mut added = Vec::new();
        let mut power_changed = Vec::new();

        for v in &other.vals {
            match self_map.get(&v.pk) {
                None => added.push(v.clone()),
                Some(existing) if existing.power != v.power => power_changed.push(v.clone()),
                _ => {}
            }
        }

        let other_keys: HashSet<&PublicKeyBytes> = other.vals.iter().map(|v| &v.pk).collect();
        let removed = self
            .vals
            .iter()
            .filter(|v| !other_keys.contains(&v.pk))
            .cloned()
            .collect();

        (added, removed, power_changed)
    }

    /// Merge `other` into `self`.
    ///
    /// On a duplicate public key, the `other` entry wins (used for stake
    /// updates). Validators only in `self` are retained.
    pub fn merge(&mut self, other: &ValidatorSet) {
        // Index existing positions by public key.
        let mut index: HashMap<Vec<u8>, usize> = self
            .vals
            .iter()
            .enumerate()
            .map(|(i, v)| (v.pk.0.clone(), i))
            .collect();

        for v in &other.vals {
            match index.get(&v.pk.0) {
                Some(&i) => {
                    self.vals[i].power = v.power;
                }
                None => {
                    index.insert(v.pk.0.clone(), self.vals.len());
                    self.vals.push(v.clone());
                }
            }
        }
    }
}

// ── Display ──────────────────────────────────────────────────────────────

impl fmt::Display for ValidatorSet {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "ValidatorSet(n={}, total_power={})",
            self.len(),
            self.total_power()
        )
    }
}

// ── Manager ──────────────────────────────────────────────────────────────

#[derive(Clone)]
struct ProposerCacheEntry {
    validator: Validator,
    expires_at: Instant,
}

/// Thread-safe manager for validator set operations with caching and metrics.
///
/// # Cloning
///
/// Cloning shares state via `Arc`. Clones observe each other's writes.
#[derive(Clone)]
pub struct ValidatorSetManager {
    config: Arc<ValidatorSetConfig>,
    metrics: Arc<ValidatorSetMetrics>,
    vset: Arc<Mutex<ValidatorSet>>,
    cache: Arc<Mutex<Option<LruCache<(u64, u32), ProposerCacheEntry>>>>,
    ttl: Duration,
}

impl ValidatorSetManager {
    /// Create a new manager with the given configuration and initial set.
    pub fn new(
        config: ValidatorSetConfig,
        vset: ValidatorSet,
    ) -> ValidatorSetResult<Self> {
        config.validate().map_err(ValidatorSetError::Config)?;

        let metrics = if config.enable_metrics {
            ValidatorSetMetrics::new().unwrap_or_else(|e| {
                warn!(
                    error = %e,
                    "validator set metrics already registered; using unregistered instance"
                );
                ValidatorSetMetrics::unregistered()
            })
        } else {
            ValidatorSetMetrics::unregistered()
        };

        let cache = if config.enable_cache {
            let size = NonZeroUsize::new(config.cache_size)
                .ok_or_else(|| ValidatorSetError::Config("cache_size must be > 0".into()))?;
            Some(LruCache::new(size))
        } else {
            None
        };

        let ttl = Duration::from_secs(config.cache_ttl_secs);

        let manager = Self {
            config: Arc::new(config),
            metrics: Arc::new(metrics),
            vset: Arc::new(Mutex::new(vset)),
            cache: Arc::new(Mutex::new(cache)),
            ttl,
        };

        manager.update_metrics();
        Ok(manager)
    }

    /// Snapshot of the current validator set.
    pub fn get(&self) -> ValidatorSet {
        self.vset.lock().clone()
    }

    /// Replace the validator set.
    ///
    /// If `config.validate_on_create` is `true`, the new set is validated
    /// before being installed; otherwise it is accepted as-is (an empty set
    /// triggers a `warn!`).
    ///
    /// On success the proposer cache is cleared.
    pub fn update(&self, new_vset: ValidatorSet) -> ValidatorSetResult<()> {
        if self.config.validate_on_create {
            ValidatorSet::new(new_vset.vals.clone(), usize::MAX)?;
        } else if new_vset.vals.is_empty() {
            warn!("updating to an empty validator set with validation disabled");
        }

        let old = {
            let mut guard = self.vset.lock();
            let old = guard.clone();
            *guard = new_vset;
            old
        };

        // Clear the cache after the new set is installed.
        if let Some(cache) = self.cache.lock().as_mut() {
            cache.clear();
        }

        if self.config.log_changes {
            let (added, removed, power_changed) = old.diff(&self.vset.lock());
            if !added.is_empty() || !removed.is_empty() || !power_changed.is_empty() {
                info!(
                    added = added.len(),
                    removed = removed.len(),
                    power_changed = power_changed.len(),
                    "validator set updated"
                );
            }
            if !added.is_empty() {
                self.metrics.record_update("added");
            }
            if !removed.is_empty() {
                self.metrics.record_update("removed");
            }
            if !power_changed.is_empty() {
                self.metrics.record_update("power_changed");
            }
        }

        self.update_metrics();
        Ok(())
    }

    /// Proposer for `(height, round)`, cached.
    ///
    /// Returns `Err(ValidatorSetError::EmptySet)` if the set is empty.
    pub fn proposer_for(&self, height: u64, round: u32) -> ValidatorSetResult<Validator> {
        self.metrics.record_proposer_check();

        let key = (height, round);
        let now = Instant::now();

        // Try cache first.
        if self.config.enable_cache {
            let mut guard = self.cache.lock();
            if let Some(cache) = guard.as_mut() {
                if let Some(entry) = cache.get(&key) {
                    if entry.expires_at > now {
                        self.metrics.record_cache_hit();
                        trace!(height, round, "proposer cache hit");
                        return Ok(entry.validator.clone());
                    }
                    cache.pop(&key);
                }
                self.metrics.record_cache_miss();
            }
        }

        // Compute fresh.
        let val = {
            let vset = self.vset.lock();
            vset.try_proposer_for(height, round)
                .cloned()
                .ok_or(ValidatorSetError::EmptySet)?
        };

        // Store in cache.
        if self.config.enable_cache {
            let mut guard = self.cache.lock();
            if let Some(cache) = guard.as_mut() {
                cache.put(
                    key,
                    ProposerCacheEntry {
                        validator: val.clone(),
                        expires_at: now + self.ttl,
                    },
                );
            }
        }

        Ok(val)
    }

    /// Voting power of the given public key (0 if not in the set).
    #[must_use]
    pub fn power_of(&self, pk: &PublicKeyBytes) -> VotingPower {
        self.vset.lock().power_of(pk)
    }

    /// Whether the given public key is in the set.
    #[must_use]
    pub fn contains(&self, pk: &PublicKeyBytes) -> bool {
        self.vset.lock().contains(pk)
    }

    /// Total voting power.
    #[must_use]
    pub fn total_power(&self) -> VotingPower {
        self.vset.lock().total_power()
    }

    /// Quorum threshold.
    #[must_use]
    pub fn quorum_threshold(&self) -> VotingPower {
        self.vset.lock().quorum_threshold()
    }

    /// Number of validators.
    #[must_use]
    pub fn len(&self) -> usize {
        self.vset.lock().len()
    }

    /// Whether the set is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.vset.lock().is_empty()
    }

    /// Canonical hash of the current set.
    #[must_use]
    pub fn hash_hex(&self) -> String {
        self.vset.lock().hash_hex()
    }

    /// Clear the proposer cache.
    pub fn clear_cache(&self) {
        if let Some(cache) = self.cache.lock().as_mut() {
            cache.clear();
            trace!("validator set cache cleared");
        }
    }

    /// Current cache size.
    #[must_use]
    pub fn cache_size(&self) -> usize {
        self.cache.lock().as_ref().map_or(0, |c| c.len())
    }

    /// Update the metrics gauges from the current set.
    fn update_metrics(&self) {
        let vset = self.vset.lock();
        self.metrics.set_validator_count(vset.len());
        self.metrics.set_total_power(vset.total_power());
        self.metrics.set_quorum_threshold(vset.quorum_threshold());
    }

    /// Snapshot of the current metrics.
    #[must_use]
    pub fn metrics_snapshot(&self) -> ValidatorSetMetricsSnapshot {
        ValidatorSetMetricsSnapshot {
            validator_count: self.metrics.validator_count.get() as usize,
            total_power: self.metrics.total_power.get() as u64,
            quorum_threshold: self.metrics.quorum_threshold.get() as u64,
            proposer_checks: self.metrics.proposer_checks.get(),
            cache_hits: self.metrics.cache_hits.get(),
            cache_misses: self.metrics.cache_misses.get(),
            cache_size: self.cache_size(),
        }
    }

    /// Configuration.
    #[must_use]
    pub fn config(&self) -> &ValidatorSetConfig {
        &self.config
    }
}

/// Snapshot of validator set metrics.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ValidatorSetMetricsSnapshot {
    pub validator_count: usize,
    pub total_power: u64,
    pub quorum_threshold: u64,
    pub proposer_checks: u64,
    pub cache_hits: u64,
    pub cache_misses: u64,
    pub cache_size: usize,
}

// ── Standalone functions (backward compat) ───────────────────────────────

/// Create a new validator set with validation.
pub fn new_validator_set(
    vals: Vec<Validator>,
    max_size: usize,
) -> ValidatorSetResult<ValidatorSet> {
    ValidatorSet::new(vals, max_size)
}

/// Validate a slice of validators without constructing a `ValidatorSet`.
pub fn validate_validator_set(vals: &[Validator]) -> ValidatorSetResult<()> {
    if vals.is_empty() {
        return Err(ValidatorSetError::EmptySet);
    }
    let mut seen = HashSet::with_capacity(vals.len());
    for v in vals {
        if v.power == 0 {
            return Err(ValidatorSetError::ZeroPower);
        }
        let key = hex::encode(&v.pk.0);
        if !seen.insert(key.clone()) {
            return Err(ValidatorSetError::DuplicatePublicKey(key));
        }
    }
    Ok(())
}

// ── Tests ─────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_validator(pk_byte: u8, power: VotingPower) -> Validator {
        Validator {
            pk: PublicKeyBytes(vec![pk_byte; 32]),
            power,
        }
    }

    fn make_vset(vals: Vec<Validator>) -> ValidatorSet {
        ValidatorSet { vals }
    }

    // ── Basic queries ───────────────────────────────────────────────────

    #[test]
    fn test_total_power() {
        let vset = make_vset(vec![
            make_validator(1, 10),
            make_validator(2, 20),
            make_validator(3, 30),
        ]);
        assert_eq!(vset.total_power(), 60);
    }

    #[test]
    fn test_total_power_saturates() {
        let vset = make_vset(vec![
            make_validator(1, u64::MAX),
            make_validator(2, u64::MAX),
        ]);
        assert_eq!(vset.total_power(), u64::MAX);
    }

    #[test]
    fn test_power_of() {
        let vset = make_vset(vec![make_validator(1, 10), make_validator(2, 20)]);
        assert_eq!(vset.power_of(&PublicKeyBytes(vec![1; 32])), 10);
        assert_eq!(vset.power_of(&PublicKeyBytes(vec![2; 32])), 20);
        assert_eq!(vset.power_of(&PublicKeyBytes(vec![3; 32])), 0);
    }

    #[test]
    fn test_contains() {
        let vset = make_vset(vec![make_validator(1, 10)]);
        assert!(vset.contains(&PublicKeyBytes(vec![1; 32])));
        assert!(!vset.contains(&PublicKeyBytes(vec![2; 32])));
    }

    // ── Proposer selection ──────────────────────────────────────────────

    #[test]
    fn test_proposer_round_robin() {
        let vset = make_vset(vec![
            make_validator(1, 10),
            make_validator(2, 20),
            make_validator(3, 30),
        ]);
        assert_eq!(vset.proposer_for(0, 0).pk.0[0], 1);
        assert_eq!(vset.proposer_for(1, 0).pk.0[0], 2);
        assert_eq!(vset.proposer_for(2, 0).pk.0[0], 3);
        assert_eq!(vset.proposer_for(3, 0).pk.0[0], 1);
        assert_eq!(vset.proposer_for(0, 1).pk.0[0], 2);
    }

    #[test]
    fn test_proposer_for_large_height_does_not_truncate() {
        // Regression: the previous implementation cast `height as usize`
        // which truncates on 32-bit platforms. Now uses u64 modulo.
        let vset = make_vset(vec![
            make_validator(1, 1),
            make_validator(2, 1),
            make_validator(3, 1),
        ]);
        let h = u64::MAX;
        // Should not panic; pick a deterministic validator.
        let _ = vset.proposer_for(h, 0);
    }

    #[test]
    fn test_try_proposer_for_empty() {
        let vset = ValidatorSet { vals: vec![] };
        assert!(vset.try_proposer_for(0, 0).is_none());
    }

    #[test]
    #[should_panic(expected = "empty set")]
    fn test_proposer_for_empty_set_panics() {
        let vset = ValidatorSet { vals: vec![] };
        let _ = vset.proposer_for(0, 0);
    }

    // ── Quorum ──────────────────────────────────────────────────────────

    #[test]
    fn test_quorum_threshold() {
        let v = |n| make_validator(n, 1);
        assert_eq!(make_vset(vec![v(1), v(2), v(3)]).quorum_threshold(), 3);
        assert_eq!(make_vset(vec![v(1), v(2), v(3), v(4)]).quorum_threshold(), 3);
        assert_eq!(make_vset(vec![make_validator(1, 100)]).quorum_threshold(), 67);
    }

    #[test]
    fn test_quorum_threshold_saturates() {
        let vset = make_vset(vec![make_validator(1, u64::MAX)]);
        // total = u64::MAX, threshold = floor(u64::MAX * 2 / 3) + 1 (saturated).
        // Should not panic on overflow.
        let _ = vset.quorum_threshold();
    }

    // ── Hash ────────────────────────────────────────────────────────────

    #[test]
    fn test_hash_order_independent() {
        let a = make_vset(vec![
            make_validator(2, 20),
            make_validator(1, 10),
            make_validator(3, 30),
        ]);
        let b = make_vset(vec![
            make_validator(1, 10),
            make_validator(2, 20),
            make_validator(3, 30),
        ]);
        assert_eq!(a.hash_hex(), b.hash_hex());
    }

    #[test]
    fn test_hash_changes_with_power() {
        let a = make_vset(vec![make_validator(1, 10)]);
        let b = make_vset(vec![make_validator(1, 11)]);
        assert_ne!(a.hash_hex(), b.hash_hex());
    }

    // ── Validation ──────────────────────────────────────────────────────

    #[test]
    fn test_validation_duplicate_pk() {
        let pk = PublicKeyBytes(vec![1; 32]);
        let vals = vec![
            Validator { pk: pk.clone(), power: 10 },
            Validator { pk, power: 20 },
        ];
        assert!(matches!(
            ValidatorSet::new(vals, 10),
            Err(ValidatorSetError::DuplicatePublicKey(_))
        ));
    }

    #[test]
    fn test_validation_zero_power() {
        let vals = vec![Validator {
            pk: PublicKeyBytes(vec![1; 32]),
            power: 0,
        }];
        assert_eq!(
            ValidatorSet::new(vals, 10),
            Err(ValidatorSetError::ZeroPower)
        );
    }

    #[test]
    fn test_validation_empty() {
        assert_eq!(
            ValidatorSet::new(vec![], 10),
            Err(ValidatorSetError::EmptySet)
        );
    }

    #[test]
    fn test_validation_too_large() {
        let vals: Vec<Validator> = (0..15)
            .map(|i| Validator {
                pk: PublicKeyBytes(vec![i; 32]),
                power: 1,
            })
            .collect();
        assert!(matches!(
            ValidatorSet::new(vals, 10),
            Err(ValidatorSetError::TooLarge { count: 15, max: 10 })
        ));
    }

    // ── Diff & merge ────────────────────────────────────────────────────

    #[test]
    fn test_diff() {
        let a = make_vset(vec![make_validator(1, 10), make_validator(2, 20)]);
        let b = make_vset(vec![make_validator(1, 10), make_validator(3, 30)]);
        let (added, removed, power_changed) = a.diff(&b);
        assert_eq!(added.len(), 1);
        assert_eq!(added[0].pk.0[0], 3);
        assert_eq!(removed.len(), 1);
        assert_eq!(removed[0].pk.0[0], 2);
        assert!(power_changed.is_empty());
    }

    #[test]
    fn test_diff_power_changed() {
        let a = make_vset(vec![make_validator(1, 10)]);
        let b = make_vset(vec![make_validator(1, 20)]);
        let (added, removed, changed) = a.diff(&b);
        assert!(added.is_empty());
        assert!(removed.is_empty());
        assert_eq!(changed.len(), 1);
        assert_eq!(changed[0].power, 20);
    }

    #[test]
    fn test_merge_updates_and_adds() {
        let mut a = make_vset(vec![make_validator(1, 10), make_validator(2, 20)]);
        let b = make_vset(vec![make_validator(2, 25), make_validator(3, 30)]);
        a.merge(&b);
        // validator 1 unchanged.
        assert_eq!(a.power_of(&PublicKeyBytes(vec![1; 32])), 10);
        // validator 2 power updated.
        assert_eq!(a.power_of(&PublicKeyBytes(vec![2; 32])), 25);
        // validator 3 added.
        assert_eq!(a.power_of(&PublicKeyBytes(vec![3; 32])), 30);
        assert_eq!(a.len(), 3);
    }

    // ── Manager ─────────────────────────────────────────────────────────

    #[test]
    fn test_manager_cache_hit() {
        let config = ValidatorSetConfig {
            enable_cache: true,
            cache_size: 10,
            ..Default::default()
        };
        let vset = make_vset(vec![
            make_validator(1, 10),
            make_validator(2, 20),
            make_validator(3, 30),
        ]);
        let manager = ValidatorSetManager::new(config, vset).unwrap();
        let p1 = manager.proposer_for(0, 0).unwrap();
        let p2 = manager.proposer_for(0, 0).unwrap();
        assert_eq!(p1.pk.0[0], p2.pk.0[0]);
        let snap = manager.metrics_snapshot();
        assert_eq!(snap.cache_misses, 1);
        assert_eq!(snap.cache_hits, 1);
    }

    #[test]
    fn test_manager_clear_cache() {
        let config = ValidatorSetConfig {
            enable_cache: true,
            cache_size: 10,
            ..Default::default()
        };
        let vset = make_vset(vec![
            make_validator(1, 10),
            make_validator(2, 20),
            make_validator(3, 30),
        ]);
        let manager = ValidatorSetManager::new(config, vset).unwrap();
        manager.proposer_for(0, 0).unwrap();
        assert!(manager.cache_size() > 0);
        manager.clear_cache();
        assert_eq!(manager.cache_size(), 0);
    }

    #[test]
    fn test_manager_update_invalidates_cache() {
        let config = ValidatorSetConfig::default();
        let vset = make_vset(vec![make_validator(1, 10)]);
        let manager = ValidatorSetManager::new(config, vset).unwrap();
        let p1 = manager.proposer_for(0, 0).unwrap();
        assert_eq!(p1.pk.0[0], 1);

        // Replace with a set whose first validator has a different key.
        let new_vset = make_vset(vec![make_validator(2, 10)]);
        manager.update(new_vset).unwrap();

        let p2 = manager.proposer_for(0, 0).unwrap();
        assert_eq!(p2.pk.0[0], 2, "cache must be invalidated on update");
    }

    #[test]
    fn test_manager_update_rejects_empty_by_default() {
        let config = ValidatorSetConfig::default(); // validate_on_create: true
        let vset = make_vset(vec![make_validator(1, 10)]);
        let manager = ValidatorSetManager::new(config, vset).unwrap();
        let result = manager.update(ValidatorSet { vals: vec![] });
        assert!(matches!(result, Err(ValidatorSetError::EmptySet)));
    }

    #[test]
    fn test_manager_update_accepts_empty_when_validation_disabled() {
        let config = ValidatorSetConfig {
            validate_on_create: false,
            ..Default::default()
        };
        let vset = make_vset(vec![make_validator(1, 10)]);
        let manager = ValidatorSetManager::new(config, vset).unwrap();
        assert!(manager.update(ValidatorSet { vals: vec![] }).is_ok());
        assert!(manager.is_empty());
    }

    #[test]
    fn test_manager_proposer_for_empty_returns_err() {
        let config = ValidatorSetConfig {
            validate_on_create: false,
            ..Default::default()
        };
        let manager =
            ValidatorSetManager::new(config, ValidatorSet { vals: vec![] }).unwrap();
        assert!(matches!(
            manager.proposer_for(0, 0),
            Err(ValidatorSetError::EmptySet)
        ));
    }

    #[test]
    fn test_manager_rejects_invalid_config() {
        let config = ValidatorSetConfig {
            cache_size: 0,
            ..Default::default()
        };
        let vset = make_vset(vec![make_validator(1, 10)]);
        assert!(matches!(
            ValidatorSetManager::new(config, vset),
            Err(ValidatorSetError::Config(_))
        ));
    }

    #[test]
    fn test_metrics_unregistered_is_repeatable() {
        // Regression: the derived-style fallback chained `.unwrap()`, which
        // could panic on a name collision in the default registry.
        let _a = ValidatorSetMetrics::unregistered();
        let _b = ValidatorSetMetrics::unregistered();
        let _c = ValidatorSetMetrics::default();
    }

    // ── Misc ────────────────────────────────────────────────────────────

    #[test]
    fn test_is_empty_and_len() {
        let vset = ValidatorSet { vals: vec![] };
        assert!(vset.is_empty());
        assert_eq!(vset.len(), 0);
        let vset = make_vset(vec![make_validator(1, 10)]);
        assert!(!vset.is_empty());
        assert_eq!(vset.len(), 1);
    }

    #[test]
    fn test_iter() {
        let vset = make_vset(vec![make_validator(1, 10), make_validator(2, 20)]);
        let pks: Vec<u8> = vset.iter().map(|v| v.pk.0[0]).collect();
        assert_eq!(pks, vec![1, 2]);
    }

    #[test]
    fn test_display() {
        let vset = make_vset(vec![make_validator(1, 10), make_validator(2, 20)]);
        let s = format!("{vset}");
        assert!(s.contains("n=2"));
        assert!(s.contains("total_power=30"));
    }

    #[test]
    fn test_validate_validator_set_helper() {
        assert!(validate_validator_set(&[]).is_err());
        assert!(validate_validator_set(&[make_validator(1, 0)]).is_err());
        assert!(validate_validator_set(&[make_validator(1, 1)]).is_ok());
    }
}
