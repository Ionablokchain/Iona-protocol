//! Quorum calculator with diagnostic output for IONA.
//!
//! When consensus stalls, this module tells you exactly WHY:
//! ```text
//! NO_QUORUM: have=2/3 power, voted=[a1b2c3d4,...], missing=[e5f6...,...]
//! validators: 2/3 connected, quorum_ok=false
//! ```
//!
//! # Concurrency
//!
//! [`QuorumDiagManager`] is `Clone + Send + Sync`. All internal state is
//! behind [`parking_lot::Mutex`], which does not poison on panic. Clones
//! share state via `Arc`.
//!
//! # Cache correctness
//!
//! The diagnostic cache is keyed on a blake3 fingerprint of the validator
//! set **including per-validator powers** and the sorted voter set. Two
//! validator sets with identical total power but different distributions
//! produce different fingerprints (this was a correctness bug in earlier
//! versions).
//!
//! Entries expire after `QuorumDiagConfig::cache_ttl_secs`.

use crate::consensus::validator_set::{Validator, ValidatorSet, VotingPower};
use crate::crypto::PublicKeyBytes;
use crate::types::Hash32;
use lru::LruCache;
use parking_lot::Mutex;
use prometheus::{register_counter, register_gauge, Counter, Gauge};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::fmt;
use std::num::NonZeroUsize;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tracing::{debug, trace};

// ── Configuration ─────────────────────────────────────────────────────────

/// Configuration for the quorum diagnostics subsystem.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct QuorumDiagConfig {
    /// Whether to enable caching of diagnostic results.
    pub enable_cache: bool,
    /// Maximum number of entries in the cache.
    pub cache_size: usize,
    /// Cache TTL in seconds. Entries older than this are treated as misses.
    pub cache_ttl_secs: u64,
    /// Whether to enable metrics.
    pub enable_metrics: bool,
    /// Whether to log diagnostic results.
    pub log_diagnostics: bool,
}

impl Default for QuorumDiagConfig {
    fn default() -> Self {
        Self {
            enable_cache: true,
            cache_size: 128,
            cache_ttl_secs: 30,
            enable_metrics: true,
            log_diagnostics: true,
        }
    }
}

impl QuorumDiagConfig {
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

/// Prometheus metrics for the quorum diagnostics subsystem.
///
/// # Registration
///
/// [`QuorumDiagMetrics::new`] registers with the **default** Prometheus
/// registry and can only be called once per process. Use
/// [`QuorumDiagMetrics::unregistered`] for a fail-free instance
/// (that's what `Default` does).
#[derive(Clone)]
pub struct QuorumDiagMetrics {
    pub quorum_checks: Counter,
    pub quorum_ok: Counter,
    pub quorum_fail: Counter,
    pub cache_hits: Counter,
    pub cache_misses: Counter,
    pub connectivity_checks: Counter,
    pub cache_size: Gauge,
}

impl QuorumDiagMetrics {
    /// Register all metrics with the default Prometheus registry.
    pub fn new() -> Result<Self, prometheus::Error> {
        Ok(Self {
            quorum_checks: prometheus::register_counter!(
                "iona_quorum_checks_total",
                "Total quorum checks performed"
            )?,
            quorum_ok: prometheus::register_counter!(
                "iona_quorum_ok_total",
                "Quorum checks that succeeded"
            )?,
            quorum_fail: prometheus::register_counter!(
                "iona_quorum_fail_total",
                "Quorum checks that failed"
            )?,
            cache_hits: prometheus::register_counter!(
                "iona_quorum_cache_hits_total",
                "Cache hits for quorum diagnostics"
            )?,
            cache_misses: prometheus::register_counter!(
                "iona_quorum_cache_misses_total",
                "Cache misses for quorum diagnostics"
            )?,
            connectivity_checks: prometheus::register_counter!(
                "iona_connectivity_checks_total",
                "Total connectivity checks"
            )?,
            cache_size: prometheus::register_gauge!(
                "iona_quorum_cache_size",
                "Current size of the quorum diagnostics cache"
            )?,
        })
    }

    /// Create an **unregistered** metrics bundle.
    ///
    /// Never fails, never registers. Suitable for tests or a custom registry.
    pub fn unregistered() -> Self {
        let mk = |name: &str, help: &str| {
            Counter::new(name, help).expect("counter construction is infallible")
        };
        Self {
            quorum_checks: mk("iona_quorum_checks_total", "Total quorum checks performed"),
            quorum_ok: mk("iona_quorum_ok_total", "Quorum checks that succeeded"),
            quorum_fail: mk("iona_quorum_fail_total", "Quorum checks that failed"),
            cache_hits: mk(
                "iona_quorum_cache_hits_total",
                "Cache hits for quorum diagnostics",
            ),
            cache_misses: mk(
                "iona_quorum_cache_misses_total",
                "Cache misses for quorum diagnostics",
            ),
            connectivity_checks: mk(
                "iona_connectivity_checks_total",
                "Total connectivity checks",
            ),
            cache_size: Gauge::new(
                "iona_quorum_cache_size",
                "Current size of the quorum diagnostics cache",
            )
            .expect("gauge construction is infallible"),
        }
    }

    pub fn record_check(&self, has_quorum: bool) {
        self.quorum_checks.inc();
        if has_quorum {
            self.quorum_ok.inc();
        } else {
            self.quorum_fail.inc();
        }
    }

    pub fn record_cache_hit(&self) {
        self.cache_hits.inc();
    }

    pub fn record_cache_miss(&self) {
        self.cache_misses.inc();
    }

    pub fn record_connectivity(&self) {
        self.connectivity_checks.inc();
    }

    pub fn set_cache_size(&self, size: usize) {
        self.cache_size.set(size as f64);
    }
}

impl Default for QuorumDiagMetrics {
    fn default() -> Self {
        Self::unregistered()
    }
}

// ── QuorumDiagnostic ─────────────────────────────────────────────────────

/// Diagnostic information about quorum status.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct QuorumDiagnostic {
    pub total_validators: usize,
    pub total_power: VotingPower,
    pub quorum_threshold: VotingPower,
    pub current_power: VotingPower,
    pub has_quorum: bool,
    pub voted: Vec<String>,
    pub missing: Vec<String>,
    pub reason: Option<String>,
}

impl fmt::Display for QuorumDiagnostic {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.has_quorum {
            write!(
                f,
                "quorum_ok: {}/{} power ({}/{} validators)",
                self.current_power,
                self.quorum_threshold,
                self.voted.len(),
                self.total_validators
            )
        } else {
            write!(
                f,
                "NO_QUORUM: have={}/{} power, voted=[{}], missing=[{}]",
                self.current_power,
                self.quorum_threshold,
                self.voted.join(","),
                self.missing.join(",")
            )
        }
    }
}

// ── QuorumCalculator ─────────────────────────────────────────────────────

/// Enhanced quorum calculator that provides diagnostics.
#[derive(Debug, Clone)]
pub struct QuorumCalculator {
    vset: ValidatorSet,
    total_power: VotingPower,
    threshold: VotingPower,
}

impl QuorumCalculator {
    /// Create a new quorum calculator for the given validator set.
    #[must_use]
    pub fn new(vset: &ValidatorSet) -> Self {
        let total = vset.total_power();
        let threshold = (total * 2 / 3) + 1;
        Self {
            vset: vset.clone(),
            total_power: total,
            threshold,
        }
    }

    /// Quorum threshold (`floor(total × 2 / 3) + 1`).
    #[must_use]
    pub fn threshold(&self) -> VotingPower {
        self.threshold
    }

    /// Total voting power in the validator set.
    #[must_use]
    pub fn total_power(&self) -> VotingPower {
        self.total_power
    }

    /// Number of validators.
    #[must_use]
    pub fn validator_count(&self) -> usize {
        self.vset.vals.len()
    }

    /// Check whether a set of voters reaches quorum.
    #[must_use]
    pub fn check(&self, voters: &[PublicKeyBytes]) -> QuorumDiagnostic {
        let voter_set: HashSet<&PublicKeyBytes> = voters.iter().collect();
        let mut current_power: VotingPower = 0;
        let mut voted = Vec::new();
        let mut missing = Vec::new();

        for val in &self.vset.vals {
            let pk_hex = hex::encode(&val.pk.0[..8]);
            if voter_set.contains(&val.pk) {
                current_power += val.power;
                voted.push(pk_hex);
            } else {
                missing.push(pk_hex);
            }
        }

        let has_quorum = current_power >= self.threshold;
        let reason = if has_quorum {
            None
        } else {
            Some(format!(
                "missing_quorum: have={} need={} (voted={}/{} validators)",
                current_power,
                self.threshold,
                voted.len(),
                self.vset.vals.len(),
            ))
        };

        QuorumDiagnostic {
            total_validators: self.vset.vals.len(),
            total_power: self.total_power,
            quorum_threshold: self.threshold,
            current_power,
            has_quorum,
            voted,
            missing,
            reason,
        }
    }

    /// Check quorum for a specific block from a vote map.
    #[must_use]
    pub fn check_for_block(
        &self,
        votes: &HashMap<PublicKeyBytes, Option<Hash32>>,
        target_block: &Hash32,
    ) -> QuorumDiagnostic {
        let voters: Vec<PublicKeyBytes> = votes
            .iter()
            .filter(|(_, bid)| bid.as_ref() == Some(target_block))
            .map(|(pk, _)| pk.clone())
            .collect();
        self.check(&voters)
    }

    /// Human-readable summary of quorum status.
    #[must_use]
    pub fn summary(&self, voters: &[PublicKeyBytes]) -> String {
        self.check(voters).to_string()
    }

    /// Sanity check: can the validator set ever reach quorum?
    ///
    /// This is `true` for any well-formed set (since `threshold ≤ total`).
    /// It does **not** depend on the current voters. Prefer
    /// [`validators_needed`](Self::validators_needed) to compute the actual
    /// gap to quorum.
    #[must_use]
    pub fn can_reach_quorum(&self, _current_voters: &[PublicKeyBytes]) -> bool {
        self.total_power >= self.threshold
    }

    /// Minimum number of additional validators needed to reach quorum.
    ///
    /// Counts by validator (not by power), greedily choosing the
    /// highest-power disconnected validators first.
    ///
    /// Returns [`usize::MAX`] if quorum is unreachable from the current
    /// set — this cannot happen for a well-formed validator set (it would
    /// require `threshold > total`), but is a safe sentinel.
    #[must_use]
    pub fn validators_needed(&self, current_voters: &[PublicKeyBytes]) -> usize {
        let diag = self.check(current_voters);
        if diag.has_quorum {
            return 0;
        }

        let voter_set: HashSet<&PublicKeyBytes> = current_voters.iter().collect();
        let mut remaining: Vec<VotingPower> = self
            .vset
            .vals
            .iter()
            .filter(|v| !voter_set.contains(&v.pk))
            .map(|v| v.power)
            .collect();

        remaining.sort_unstable_by(|a, b| b.cmp(a));

        let deficit = self.threshold.saturating_sub(diag.current_power);
        let mut accumulated: u64 = 0;
        for (i, p) in remaining.iter().enumerate() {
            accumulated = accumulated.saturating_add(*p);
            if accumulated >= deficit {
                return i + 1;
            }
        }
        // Even all remaining validators cannot reach quorum.
        usize::MAX
    }
}

// ── ValidatorConnectivity ───────────────────────────────────────────────

/// P2P connectivity diagnostic for validators.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ValidatorConnectivity {
    pub total_validators: usize,
    pub connected_validators: usize,
    pub connected: Vec<String>,
    pub disconnected: Vec<String>,
    pub has_quorum_connectivity: bool,
}

impl fmt::Display for ValidatorConnectivity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "validators: {}/{} connected, quorum_ok={}",
            self.connected_validators, self.total_validators, self.has_quorum_connectivity
        )
    }
}

/// Check which validators are reachable from a set of connected peer public keys.
#[must_use]
pub fn check_validator_connectivity(
    vset: &ValidatorSet,
    connected_pks: &[PublicKeyBytes],
) -> ValidatorConnectivity {
    let connected_set: HashSet<&PublicKeyBytes> = connected_pks.iter().collect();
    let total = vset.total_power();
    let threshold = if total == 0 { 1 } else { (total * 2 / 3) + 1 };

    let mut connected = Vec::new();
    let mut disconnected = Vec::new();
    let mut connected_power: VotingPower = 0;

    for val in &vset.vals {
        let pk_hex = hex::encode(&val.pk.0[..8]);
        if connected_set.contains(&val.pk) {
            connected.push(pk_hex);
            connected_power = connected_power.saturating_add(val.power);
        } else {
            disconnected.push(pk_hex);
        }
    }

    ValidatorConnectivity {
        total_validators: vset.vals.len(),
        connected_validators: connected.len(),
        connected,
        disconnected,
        has_quorum_connectivity: connected_power >= threshold,
    }
}

// ── QuorumDiagManager (thread-safe) ─────────────────────────────────────

/// Cache key: a 32-byte blake3 fingerprint of `(validator set, sorted voters)`.
///
/// The fingerprint includes every validator's public key and power, so two
/// validator sets with the same total power but different distributions
/// produce different keys.
fn cache_fingerprint(vset: &ValidatorSet, voters: &[PublicKeyBytes]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"iona/quorum_diag/cache/v1:");

    // Canonical: validator set in order, with per-validator power.
    hasher.update(&(vset.vals.len() as u64).to_le_bytes());
    for v in &vset.vals {
        hasher.update(&v.pk.0);
        hasher.update(&v.power.to_le_bytes());
    }

    // Canonical: voters sorted by public key bytes.
    let mut sorted: Vec<&PublicKeyBytes> = voters.iter().collect();
    sorted.sort_unstable_by(|a, b| a.0.cmp(&b.0));
    hasher.update(&(sorted.len() as u64).to_le_bytes());
    for pk in sorted {
        hasher.update(&pk.0);
    }

    *hasher.finalize().as_bytes()
}

type CacheEntry = (QuorumDiagnostic, Instant);
type Cache = LruCache<[u8; 32], CacheEntry>;

/// Thread-safe manager for quorum diagnostics with caching and metrics.
#[derive(Clone)]
pub struct QuorumDiagManager {
    config: Arc<QuorumDiagConfig>,
    metrics: Arc<QuorumDiagMetrics>,
    cache: Arc<Mutex<Option<Cache>>>,
    ttl: Duration,
}

impl QuorumDiagManager {
    /// Create a new manager with the given configuration.
    pub fn new(config: QuorumDiagConfig) -> Result<Self, String> {
        config.validate()?;

        // Try to register with the default Prometheus registry; fall back to
        // an unregistered instance if names are already taken (e.g. a second
        // manager in the same process). Never panic.
        let metrics = if config.enable_metrics {
            QuorumDiagMetrics::new().unwrap_or_else(|e| {
                tracing::warn!(
                    error = %e,
                    "quorum diag metrics already registered; using unregistered instance"
                );
                QuorumDiagMetrics::unregistered()
            })
        } else {
            QuorumDiagMetrics::unregistered()
        };

        let cache = if config.enable_cache {
            let size = NonZeroUsize::new(config.cache_size).ok_or("cache_size must be > 0")?;
            Some(LruCache::new(size))
        } else {
            None
        };

        let ttl = Duration::from_secs(config.cache_ttl_secs);

        Ok(Self {
            config: Arc::new(config),
            metrics: Arc::new(metrics),
            cache: Arc::new(Mutex::new(cache)),
            ttl,
        })
    }

    /// Check quorum, using the cache if enabled.
    pub fn check(&self, vset: &ValidatorSet, voters: &[PublicKeyBytes]) -> QuorumDiagnostic {
        let key = cache_fingerprint(vset, voters);
        let now = Instant::now();

        // Try cache first.
        if self.config.enable_cache {
            let mut guard = self.cache.lock();
            if let Some(cache) = guard.as_mut() {
                if let Some((diag, stored_at)) = cache.get(&key) {
                    if now.duration_since(*stored_at) < self.ttl {
                        self.metrics.record_cache_hit();
                        trace!("quorum cache hit");
                        return diag.clone();
                    }
                    // Expired: drop and treat as a miss.
                    cache.pop(&key);
                }
                self.metrics.record_cache_miss();
            }
        }

        // Compute fresh.
        let qc = QuorumCalculator::new(vset);
        let diag = qc.check(voters);

        // Record metrics.
        self.metrics.record_check(diag.has_quorum);

        // Log: failures at `debug!`, successes at `trace!`.
        if self.config.log_diagnostics {
            if !diag.has_quorum {
                debug!(
                    current_power = diag.current_power,
                    threshold = diag.quorum_threshold,
                    voted = diag.voted.len(),
                    missing = diag.missing.len(),
                    "quorum check failed"
                );
            } else {
                trace!(
                    current_power = diag.current_power,
                    threshold = diag.quorum_threshold,
                    "quorum check passed"
                );
            }
        }

        // Store in cache.
        if self.config.enable_cache {
            let mut guard = self.cache.lock();
            if let Some(cache) = guard.as_mut() {
                cache.put(key, (diag.clone(), now));
                self.metrics.set_cache_size(cache.len());
            }
        }

        diag
    }

    /// Check quorum for a specific block, going through the cache.
    #[must_use]
    pub fn check_for_block(
        &self,
        vset: &ValidatorSet,
        votes: &HashMap<PublicKeyBytes, Option<Hash32>>,
        target_block: &Hash32,
    ) -> QuorumDiagnostic {
        let voters: Vec<PublicKeyBytes> = votes
            .iter()
            .filter(|(_, bid)| bid.as_ref() == Some(target_block))
            .map(|(pk, _)| pk.clone())
            .collect();
        self.check(vset, &voters)
    }

    /// Check connectivity.
    pub fn check_connectivity(
        &self,
        vset: &ValidatorSet,
        connected_pks: &[PublicKeyBytes],
    ) -> ValidatorConnectivity {
        self.metrics.record_connectivity();
        let result = check_validator_connectivity(vset, connected_pks);
        if self.config.log_diagnostics {
            if !result.has_quorum_connectivity {
                debug!(
                    connected = result.connected_validators,
                    total = result.total_validators,
                    "connectivity below quorum"
                );
            } else {
                trace!(
                    connected = result.connected_validators,
                    total = result.total_validators,
                    "connectivity check passed"
                );
            }
        }
        result
    }

    /// Clear the cache.
    pub fn clear_cache(&self) {
        if let Some(cache) = self.cache.lock().as_mut() {
            cache.clear();
            self.metrics.set_cache_size(0);
            trace!("quorum cache cleared");
        }
    }

    /// Current cache size.
    pub fn cache_size(&self) -> usize {
        self.cache.lock().as_ref().map_or(0, |c| c.len())
    }

    /// Metrics snapshot.
    pub fn metrics_snapshot(&self) -> QuorumDiagMetricsSnapshot {
        QuorumDiagMetricsSnapshot {
            quorum_checks: self.metrics.quorum_checks.get(),
            quorum_ok: self.metrics.quorum_ok.get(),
            quorum_fail: self.metrics.quorum_fail.get(),
            cache_hits: self.metrics.cache_hits.get(),
            cache_misses: self.metrics.cache_misses.get(),
            connectivity_checks: self.metrics.connectivity_checks.get(),
            cache_size: self.cache_size(),
        }
    }

    /// Configuration.
    pub fn config(&self) -> &QuorumDiagConfig {
        &self.config
    }
}

/// Snapshot of quorum diagnostics metrics.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct QuorumDiagMetricsSnapshot {
    pub quorum_checks: u64,
    pub quorum_ok: u64,
    pub quorum_fail: u64,
    pub cache_hits: u64,
    pub cache_misses: u64,
    pub connectivity_checks: u64,
    pub cache_size: usize,
}

// ── Standalone functions (backward compatibility) ──────────────────────

/// Convenience wrapper; prefer [`QuorumDiagManager::check`].
#[deprecated(since = "30.0.0", note = "use QuorumDiagManager::check")]
pub fn check_quorum(vset: &ValidatorSet, voters: &[PublicKeyBytes]) -> QuorumDiagnostic {
    QuorumCalculator::new(vset).check(voters)
}

/// Convenience wrapper; prefer [`QuorumDiagManager::check_connectivity`].
#[deprecated(since = "30.0.0", note = "use QuorumDiagManager::check_connectivity")]
pub fn check_connectivity(
    vset: &ValidatorSet,
    connected_pks: &[PublicKeyBytes],
) -> ValidatorConnectivity {
    check_validator_connectivity(vset, connected_pks)
}

// ── Tests ─────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::ed25519::Ed25519Keypair;
    use crate::crypto::Signer;

    fn make_vset(n: usize) -> (ValidatorSet, Vec<PublicKeyBytes>) {
        let mut vals = Vec::with_capacity(n);
        let mut pks = Vec::with_capacity(n);
        for i in 0..n {
            let mut seed = [0u8; 32];
            seed[0] = (i + 1) as u8;
            let kp = Ed25519Keypair::from_seed(seed);
            let pk = kp.public_key();
            vals.push(Validator { pk: pk.clone(), power: 1 });
            pks.push(pk);
        }
        (ValidatorSet { vals }, pks)
    }

    fn make_weighted_vset(powers: &[VotingPower]) -> (ValidatorSet, Vec<PublicKeyBytes>) {
        let mut vals = Vec::with_capacity(powers.len());
        let mut pks = Vec::with_capacity(powers.len());
        for (i, p) in powers.iter().enumerate() {
            let mut seed = [0u8; 32];
            seed[0] = (i + 1) as u8;
            let kp = Ed25519Keypair::from_seed(seed);
            let pk = kp.public_key();
            vals.push(Validator { pk: pk.clone(), power: *p });
            pks.push(pk);
        }
        (ValidatorSet { vals }, pks)
    }

    // ── Basic quorum ────────────────────────────────────────────────────

    #[test]
    fn test_quorum_1_of_1() {
        let (vset, pks) = make_vset(1);
        let qc = QuorumCalculator::new(&vset);
        assert_eq!(qc.threshold(), 1);
        assert!(qc.check(&pks[..1]).has_quorum);
        assert!(!qc.check(&[]).has_quorum);
    }

    #[test]
    fn test_quorum_3_of_3() {
        let (vset, pks) = make_vset(3);
        let qc = QuorumCalculator::new(&vset);
        assert_eq!(qc.threshold(), 3);
        assert!(!qc.check(&pks[..1]).has_quorum);
        assert!(!qc.check(&pks[..2]).has_quorum);
        assert!(qc.check(&pks[..3]).has_quorum);
    }

    #[test]
    fn test_quorum_3_of_4() {
        let (vset, pks) = make_vset(4);
        let qc = QuorumCalculator::new(&vset);
        assert_eq!(qc.threshold(), 3);
        assert!(!qc.check(&pks[..2]).has_quorum);
        assert!(qc.check(&pks[..3]).has_quorum);
        assert!(qc.check(&pks[..4]).has_quorum);
    }

    #[test]
    fn test_weighted_quorum() {
        let (vset, pks) = make_weighted_vset(&[10, 5, 5]);
        let qc = QuorumCalculator::new(&vset);
        assert_eq!(qc.threshold(), 14);

        assert!(!qc.check(&[pks[0].clone()]).has_quorum);
        assert!(qc.check(&[pks[0].clone(), pks[1].clone()]).has_quorum);
        assert!(!qc.check(&[pks[1].clone(), pks[2].clone()]).has_quorum);
    }

    // ── Diagnostic content ──────────────────────────────────────────────

    #[test]
    fn test_diagnostic_reason() {
        let (vset, pks) = make_vset(3);
        let qc = QuorumCalculator::new(&vset);
        let diag = qc.check(&pks[..1]);
        assert!(!diag.has_quorum);
        assert!(diag.reason.as_ref().unwrap().contains("missing_quorum"));
        assert_eq!(diag.voted.len(), 1);
        assert_eq!(diag.missing.len(), 2);
    }

    #[test]
    fn test_summary_format() {
        let (vset, pks) = make_vset(3);
        let qc = QuorumCalculator::new(&vset);
        assert!(qc.summary(&pks).contains("quorum_ok"));
        assert!(qc.summary(&pks[..1]).contains("NO_QUORUM"));
    }

    #[test]
    fn test_validators_needed() {
        let (vset, pks) = make_vset(4);
        let qc = QuorumCalculator::new(&vset);
        assert_eq!(qc.validators_needed(&pks), 0);
        assert_eq!(qc.validators_needed(&pks[..2]), 1);
        assert_eq!(qc.validators_needed(&pks[..1]), 2);
        assert_eq!(qc.validators_needed(&[]), 3);
    }

    #[test]
    fn test_validators_needed_impossible_is_max() {
        // A validator set with no validators cannot reach quorum.
        let vset = ValidatorSet { vals: vec![] };
        let qc = QuorumCalculator::new(&vset);
        // threshold = 1, current = 0 → need 1, but there are none remaining.
        assert_eq!(qc.validators_needed(&[]), usize::MAX);
    }

    // ── Connectivity ────────────────────────────────────────────────────

    #[test]
    fn test_connectivity() {
        let (vset, pks) = make_vset(3);
        let conn = check_validator_connectivity(&vset, &pks[..2]);
        assert_eq!(conn.total_validators, 3);
        assert_eq!(conn.connected_validators, 2);
        assert_eq!(conn.disconnected.len(), 1);
        assert!(!conn.has_quorum_connectivity);
    }

    #[test]
    fn test_connectivity_quorum_met() {
        let (vset, pks) = make_vset(3);
        let conn = check_validator_connectivity(&vset, &pks);
        assert!(conn.has_quorum_connectivity);
    }

    // ── Cache correctness ───────────────────────────────────────────────

    #[test]
    fn test_cache_does_not_collide_on_different_power_distributions() {
        // Regression: the previous key hashed only `(total_power, count)`,
        // so two validator sets with identical total power but different
        // per-validator distributions shared a cache entry — one set's
        // diagnostic could be returned for the other.
        let (vset_a, pks_a) = make_weighted_vset(&[10, 5, 5]); // total 20, count 3
        let (vset_b, pks_b) = make_weighted_vset(&[8, 6, 6]); // total 20, count 3, different keys

        let config = QuorumDiagConfig {
            enable_cache: true,
            cache_size: 16,
            ..Default::default()
        };
        let manager = QuorumDiagManager::new(config).unwrap();

        let diag_a = manager.check(&vset_a, &pks_a[..1]);
        let diag_b = manager.check(&vset_b, &pks_b[..1]);

        // Both have the same current_power (only first validator voted), but
        // with different public keys in `voted`/`missing`. If they shared a
        // cache entry, the second call would return the first's `voted` list.
        assert_ne!(diag_a.voted, diag_b.voted);
    }

    #[test]
    fn test_cache_hit_and_ttl() {
        let config = QuorumDiagConfig {
            enable_cache: true,
            cache_size: 16,
            cache_ttl_secs: 1,
            log_diagnostics: false,
            ..Default::default()
        };
        let manager = QuorumDiagManager::new(config).unwrap();
        let (vset, pks) = make_vset(3);

        let _ = manager.check(&vset, &pks);
        let _ = manager.check(&vset, &pks);

        let snap = manager.metrics_snapshot();
        assert_eq!(snap.cache_misses, 1);
        assert_eq!(snap.cache_hits, 1);
    }

    #[test]
    fn test_cache_clear() {
        let config = QuorumDiagConfig {
            enable_cache: true,
            cache_size: 10,
            ..Default::default()
        };
        let manager = QuorumDiagManager::new(config).unwrap();
        let (vset, pks) = make_vset(3);
        manager.check(&vset, &pks);
        assert!(manager.cache_size() > 0);
        manager.clear_cache();
        assert_eq!(manager.cache_size(), 0);
    }

    #[test]
    fn test_cache_disabled() {
        let config = QuorumDiagConfig {
            enable_cache: false,
            ..Default::default()
        };
        let manager = QuorumDiagManager::new(config).unwrap();
        let (vset, pks) = make_vset(3);
        let _ = manager.check(&vset, &pks);
        let _ = manager.check(&vset, &pks);
        assert_eq!(manager.cache_size(), 0);
        let snap = manager.metrics_snapshot();
        assert_eq!(snap.cache_hits, 0);
        assert_eq!(snap.cache_misses, 0);
    }

    // ── Metrics ─────────────────────────────────────────────────────────

    #[test]
    fn test_metrics_unregistered_is_repeatable() {
        // Regression: `Default` used to chain `.unwrap()`, panicking on
        // the second instantiation in the same process.
        let _a = QuorumDiagMetrics::unregistered();
        let _b = QuorumDiagMetrics::unregistered();
        let _c = QuorumDiagMetrics::default();
    }

    #[test]
    fn test_metrics_snapshot() {
        let manager = QuorumDiagManager::new(QuorumDiagConfig::default()).unwrap();
        let (vset, pks) = make_vset(3);
        manager.check(&vset, &pks);
        manager.check_connectivity(&vset, &pks);
        let snap = manager.metrics_snapshot();
        assert!(snap.quorum_checks > 0);
        assert!(snap.connectivity_checks > 0);
    }

    // ── Config ──────────────────────────────────────────────────────────

    #[test]
    fn test_config_validation() {
        assert!(QuorumDiagConfig::default().validate().is_ok());
        assert!(QuorumDiagConfig { cache_size: 0, ..Default::default() }
            .validate()
            .is_err());
        assert!(QuorumDiagConfig { cache_ttl_secs: 0, ..Default::default() }
            .validate()
            .is_err());
    }

    #[test]
    fn test_display_impls() {
        let (vset, pks) = make_vset(3);
        let qc = QuorumCalculator::new(&vset);
        assert!(format!("{}", qc.check(&pks[..1])).contains("NO_QUORUM"));
        assert!(format!("{}", check_validator_connectivity(&vset, &pks[..2])).contains("connected"));
    }
}
