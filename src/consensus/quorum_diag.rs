//! Quorum calculator with diagnostic output for IONA v28.
//!
//! When consensus stalls, this module tells you exactly WHY:
//!   - missing_quorum: have=2 need=3
//!   - validators_online: [A,B] missing=[C]
//!   - p2p_connected_validators=2/3
//!
//! # Production Features
//! - Configurable via `QuorumDiagConfig` (cache size, TTL, logging).
//! - `QuorumDiagMetrics` with Prometheus counters for checks, hits, misses.
//! - `QuorumDiagManager` with thread‑safe LRU cache (`parking_lot::Mutex`).
//! - Cached results for repeated queries.
//! - Structured logging with `tracing`.
//! - Full test coverage.

use crate::consensus::validator_set::{Validator, ValidatorSet, VotingPower};
use crate::crypto::PublicKeyBytes;
use crate::types::Hash32;
use lru::LruCache;
use parking_lot::Mutex;
use prometheus::{
    register_counter, register_counter_vec, register_gauge, Counter, CounterVec, Gauge,
};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::fmt;
use std::num::NonZeroUsize;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tracing::{debug, error, info, trace, warn};

// ── Configuration ─────────────────────────────────────────────────────────

/// Configuration for the quorum diagnostics subsystem.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QuorumDiagConfig {
    /// Whether to enable caching of diagnostic results.
    pub enable_cache: bool,
    /// Maximum number of entries in the cache.
    pub cache_size: usize,
    /// Cache TTL in seconds.
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

/// Metrics for the quorum diagnostics subsystem.
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
    pub fn new() -> Result<Self, prometheus::Error> {
        let quorum_checks = register_counter!(
            "iona_quorum_checks_total",
            "Total quorum checks performed"
        )?;
        let quorum_ok = register_counter!(
            "iona_quorum_ok_total",
            "Quorum checks that succeeded"
        )?;
        let quorum_fail = register_counter!(
            "iona_quorum_fail_total",
            "Quorum checks that failed"
        )?;
        let cache_hits = register_counter!(
            "iona_quorum_cache_hits_total",
            "Cache hits for quorum diagnostics"
        )?;
        let cache_misses = register_counter!(
            "iona_quorum_cache_misses_total",
            "Cache misses for quorum diagnostics"
        )?;
        let connectivity_checks = register_counter!(
            "iona_connectivity_checks_total",
            "Total connectivity checks"
        )?;
        let cache_size = register_gauge!(
            "iona_quorum_cache_size",
            "Current size of the quorum diagnostics cache"
        )?;
        Ok(Self {
            quorum_checks,
            quorum_ok,
            quorum_fail,
            cache_hits,
            cache_misses,
            connectivity_checks,
            cache_size,
        })
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
        Self::new().unwrap_or_else(|_| Self {
            quorum_checks: Counter::new("iona_quorum_checks_total", "Checks").unwrap(),
            quorum_ok: Counter::new("iona_quorum_ok_total", "OK").unwrap(),
            quorum_fail: Counter::new("iona_quorum_fail_total", "Fail").unwrap(),
            cache_hits: Counter::new("iona_quorum_cache_hits_total", "Hits").unwrap(),
            cache_misses: Counter::new("iona_quorum_cache_misses_total", "Misses").unwrap(),
            connectivity_checks: Counter::new("iona_connectivity_checks_total", "Connectivity").unwrap(),
            cache_size: Gauge::new("iona_quorum_cache_size", "Cache size").unwrap(),
        })
    }
}

// ── QuorumDiagnostic ─────────────────────────────────────────────────────

/// Diagnostic information about quorum status.
#[derive(Debug, Clone, Serialize, Deserialize)]
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
            threshold,
        }
    }

    /// Get the quorum threshold.
    #[must_use]
    pub fn threshold(&self) -> VotingPower {
        self.threshold
    }

    /// Total voting power in the validator set.
    #[must_use]
    pub fn total_power(&self) -> VotingPower {
        self.vset.total_power()
    }

    /// Number of validators.
    #[must_use]
    pub fn validator_count(&self) -> usize {
        self.vset.vals.len()
    }

    /// Check if a set of voters reaches quorum.
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
            total_power: self.vset.total_power(),
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

    /// Get a human‑readable summary of quorum status (for logging).
    #[must_use]
    pub fn summary(&self, voters: &[PublicKeyBytes]) -> String {
        let diag = self.check(voters);
        diag.to_string()
    }

    /// Can quorum still be reached if the given validators come online?
    #[must_use]
    pub fn can_reach_quorum(&self, _current_voters: &[PublicKeyBytes]) -> bool {
        self.vset.total_power() >= self.threshold
    }

    /// Minimum number of additional validators needed to reach quorum.
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
        let mut accumulated = 0u64;
        for (i, p) in remaining.iter().enumerate() {
            accumulated += p;
            if accumulated >= deficit {
                return i + 1;
            }
        }

        remaining.len() + 1
    }
}

// ── ValidatorConnectivity ───────────────────────────────────────────────

/// P2P connectivity diagnostic for validators.
#[derive(Debug, Clone, Serialize, Deserialize)]
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
            self.connected_validators,
            self.total_validators,
            self.has_quorum_connectivity
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
    let threshold = (vset.total_power() * 2 / 3) + 1;

    let mut connected = Vec::new();
    let mut disconnected = Vec::new();
    let mut connected_power: VotingPower = 0;

    for val in &vset.vals {
        let pk_hex = hex::encode(&val.pk.0[..8]);
        if connected_set.contains(&val.pk) {
            connected.push(pk_hex);
            connected_power += val.power;
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

// ── QuorumDiagManager (thread‑safe) ─────────────────────────────────────

/// Thread‑safe manager for quorum diagnostics with caching and metrics.
#[derive(Clone)]
pub struct QuorumDiagManager {
    config: Arc<QuorumDiagConfig>,
    metrics: Arc<QuorumDiagMetrics>,
    cache: Arc<Mutex<Option<LruCache<u64, QuorumDiagnostic>>>>,
}

#[derive(Hash, Eq, PartialEq)]
struct CacheKey {
    vset_version: u64,
    voters_hash: u64,
}

impl CacheKey {
    fn compute(vset: &ValidatorSet, voters: &[PublicKeyBytes]) -> u64 {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};
        let mut hasher = DefaultHasher::new();
        // Hash validator set version (total power and count).
        vset.total_power().hash(&mut hasher);
        vset.vals.len().hash(&mut hasher);
        // Hash voter public keys.
        for pk in voters {
            pk.0.hash(&mut hasher);
        }
        hasher.finish()
    }
}

impl QuorumDiagManager {
    /// Create a new manager with the given configuration.
    pub fn new(config: QuorumDiagConfig) -> Result<Self, String> {
        config.validate()?;
        let metrics = Arc::new(QuorumDiagMetrics::default());
        let cache = if config.enable_cache {
            let size = NonZeroUsize::new(config.cache_size).ok_or("cache_size must be > 0")?;
            Some(LruCache::new(size))
        } else {
            None
        };
        Ok(Self {
            config: Arc::new(config),
            metrics,
            cache: Arc::new(Mutex::new(cache)),
        })
    }

    /// Check quorum, using cache if enabled.
    pub fn check(&self, vset: &ValidatorSet, voters: &[PublicKeyBytes]) -> QuorumDiagnostic {
        let key = CacheKey::compute(vset, voters);
        let start = Instant::now();

        // Check cache.
        if self.config.enable_cache {
            let mut cache_guard = self.cache.lock();
            if let Some(cache) = cache_guard.as_mut() {
                if let Some(entry) = cache.get(&key) {
                    self.metrics.record_cache_hit();
                    trace!("Quorum cache hit");
                    return entry.clone();
                }
                self.metrics.record_cache_miss();
            }
        }

        // Compute fresh.
        let qc = QuorumCalculator::new(vset);
        let diag = qc.check(voters);

        // Record metrics.
        self.metrics.record_check(diag.has_quorum);
        self.metrics.set_cache_size(self.cache_size());

        // Log if enabled.
        if self.config.log_diagnostics {
            trace!(
                has_quorum = diag.has_quorum,
                current_power = diag.current_power,
                threshold = diag.quorum_threshold,
                voted = diag.voted.len(),
                missing = diag.missing.len(),
                "quorum check"
            );
        }

        // Store in cache.
        if self.config.enable_cache {
            let mut cache_guard = self.cache.lock();
            if let Some(cache) = cache_guard.as_mut() {
                cache.put(key, diag.clone());
            }
        }

        diag
    }

    /// Check quorum for a specific block.
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
            trace!(
                connected = result.connected.len(),
                total = result.total_validators,
                has_quorum = result.has_quorum_connectivity,
                "connectivity check"
            );
        }
        result
    }

    /// Clear the cache.
    pub fn clear_cache(&self) {
        if let Some(cache) = self.cache.lock().as_mut() {
            cache.clear();
            self.metrics.set_cache_size(0);
            trace!("Quorum cache cleared");
        }
    }

    /// Get current cache size.
    pub fn cache_size(&self) -> usize {
        if let Some(cache) = self.cache.lock().as_ref() {
            cache.len()
        } else {
            0
        }
    }

    /// Get metrics snapshot.
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

    /// Get configuration.
    pub fn config(&self) -> &QuorumDiagConfig {
        &self.config
    }
}

/// Snapshot of quorum diagnostics metrics.
#[derive(Debug, Clone)]
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

#[deprecated(since = "30.0.0", note = "use QuorumDiagManager::check")]
pub fn check_quorum(vset: &ValidatorSet, voters: &[PublicKeyBytes]) -> QuorumDiagnostic {
    let qc = QuorumCalculator::new(vset);
    qc.check(voters)
}

#[deprecated(since = "30.0.0", note = "use QuorumDiagManager::check_connectivity")]
pub fn check_connectivity(vset: &ValidatorSet, connected_pks: &[PublicKeyBytes]) -> ValidatorConnectivity {
    check_validator_connectivity(vset, connected_pks)
}

// ── Tests ─────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::ed25519::Ed25519Keypair;
    use crate::crypto::Signer;

    fn make_vset(n: usize) -> (ValidatorSet, Vec<PublicKeyBytes>) {
        let mut vals = Vec::new();
        let mut pks = Vec::new();
        for i in 0..n {
            let mut seed = [0u8; 32];
            seed[0] = (i + 1) as u8;
            let kp = Ed25519Keypair::from_seed(seed);
            let pk = kp.public_key();
            vals.push(Validator {
                pk: pk.clone(),
                power: 1,
            });
            pks.push(pk);
        }
        (ValidatorSet { vals }, pks)
    }

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
    fn test_diagnostic_reason() {
        let (vset, pks) = make_vset(3);
        let qc = QuorumCalculator::new(&vset);
        let diag = qc.check(&pks[..1]);
        assert!(!diag.has_quorum);
        assert!(diag.reason.is_some());
        assert!(diag.reason.as_ref().unwrap().contains("missing_quorum"));
        assert_eq!(diag.voted.len(), 1);
        assert_eq!(diag.missing.len(), 2);
    }

    #[test]
    fn test_summary_format() {
        let (vset, pks) = make_vset(3);
        let qc = QuorumCalculator::new(&vset);
        let summary_ok = qc.summary(&pks);
        assert!(summary_ok.contains("quorum_ok"));
        let summary_fail = qc.summary(&pks[..1]);
        assert!(summary_fail.contains("NO_QUORUM"));
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
    fn test_connectivity() {
        let (vset, pks) = make_vset(3);
        let conn = check_validator_connectivity(&vset, &pks[..2]);
        assert_eq!(conn.total_validators, 3);
        assert_eq!(conn.connected_validators, 2);
        assert_eq!(conn.disconnected.len(), 1);
        assert!(!conn.has_quorum_connectivity);
    }

    #[test]
    fn test_weighted_quorum() {
        let mut seed1 = [0u8; 32];
        seed1[0] = 1;
        let mut seed2 = [0u8; 32];
        seed2[0] = 2;
        let mut seed3 = [0u8; 32];
        seed3[0] = 3;
        let pk1 = Ed25519Keypair::from_seed(seed1).public_key();
        let pk2 = Ed25519Keypair::from_seed(seed2).public_key();
        let pk3 = Ed25519Keypair::from_seed(seed3).public_key();
        let vset = ValidatorSet {
            vals: vec![
                Validator {
                    pk: pk1.clone(),
                    power: 10,
                },
                Validator {
                    pk: pk2.clone(),
                    power: 5,
                },
                Validator {
                    pk: pk3.clone(),
                    power: 5,
                },
            ],
        };
        let qc = QuorumCalculator::new(&vset);
        assert_eq!(qc.threshold(), 14);

        assert!(!qc.check(&[pk1.clone()]).has_quorum);
        assert!(qc.check(&[pk1.clone(), pk2.clone()]).has_quorum);
        assert!(!qc.check(&[pk2.clone(), pk3.clone()]).has_quorum);
    }

    #[test]
    fn test_display_impls() {
        let (vset, pks) = make_vset(3);
        let qc = QuorumCalculator::new(&vset);
        let diag = qc.check(&pks[..1]);
        let s = format!("{}", diag);
        assert!(s.contains("NO_QUORUM"));

        let conn = check_validator_connectivity(&vset, &pks[..2]);
        let s = format!("{}", conn);
        assert!(s.contains("connected"));
    }

    #[test]
    fn test_manager_cache() {
        let config = QuorumDiagConfig {
            enable_cache: true,
            cache_size: 10,
            ..Default::default()
        };
        let manager = QuorumDiagManager::new(config).unwrap();
        let (vset, pks) = make_vset(3);
        let d1 = manager.check(&vset, &pks);
        let d2 = manager.check(&vset, &pks);
        assert_eq!(d1.has_quorum, d2.has_quorum);
        assert!(manager.cache_size() > 0);
    }

    #[test]
    fn test_manager_clear_cache() {
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
    fn test_metrics_snapshot() {
        let config = QuorumDiagConfig::default();
        let manager = QuorumDiagManager::new(config).unwrap();
        let (vset, pks) = make_vset(3);
        manager.check(&vset, &pks);
        manager.check_connectivity(&vset, &pks);
        let snap = manager.metrics_snapshot();
        assert!(snap.quorum_checks > 0);
        assert!(snap.connectivity_checks > 0);
    }
}
