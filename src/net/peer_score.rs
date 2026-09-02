//! Per-peer scoring, quota enforcement, and quarantine for P2P hardening.
//!
//! This module implements a reputation system for peers in the P2P network.
//! It enforces:
//! - Per-peer message rate (msgs/sec) with token bucket
//! - Per-peer bandwidth (bytes/sec) with token bucket
//! - Per-peer max pending (in-flight) validation slots
//! - Score-based quarantine and ban with configurable thresholds
//! - Score decay: old bad behavior is forgiven over time
//! - Structured violation reasons for audit logging
//! - Optional Prometheus metrics
//!
//! # Example
//!
//! ```
//! use iona::net::peer_score::{PeerScore, PeerScoreConfig, ViolationReason};
//! use std::time::Duration;
//!
//! let config = PeerScoreConfig::default();
//! let mut score = PeerScore::new(config).unwrap();
//! if score.check_msg_quota("peer1") {
//!     // process message
//! } else {
//!     score.penalise("peer1", ViolationReason::MsgRateExceeded);
//! }
//! ```

use prometheus::{register_counter, register_gauge, Counter, Gauge};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tracing::{debug, info, warn};

// -----------------------------------------------------------------------------
// Constants (configurable defaults)
// -----------------------------------------------------------------------------

/// Default max messages per second accepted from a single peer.
pub const DEFAULT_PEER_MAX_MSGS_PER_SEC: f64 = 60.0;

/// Default max bytes per second accepted from a single peer (4 MiB/s).
pub const DEFAULT_PEER_MAX_BYTES_PER_SEC: f64 = 4_194_304.0;

/// Default max simultaneously in-flight validations queued for a single peer.
pub const DEFAULT_PEER_MAX_PENDING_VALIDATIONS: usize = 32;

/// Default score at or below which the peer is quarantined (no new connections).
pub const DEFAULT_QUARANTINE_THRESHOLD: i64 = -50;

/// Default score at or below which the peer is permanently banned.
pub const DEFAULT_BAN_THRESHOLD: i64 = -200;

/// Default fraction of score retained per decay tick (0.9 = 10% decay per tick).
const DEFAULT_DECAY_FACTOR: i64 = 9;
const DEFAULT_DECAY_DIVISOR: i64 = 10;

/// Default decay interval.
const DEFAULT_DECAY_INTERVAL_SECS: u64 = 10;

// -----------------------------------------------------------------------------
// Configuration
// -----------------------------------------------------------------------------

/// Configuration for the peer scoring system.
#[derive(Debug, Clone)]
pub struct PeerScoreConfig {
    /// Max messages per second per peer.
    pub max_msgs_per_sec: f64,
    /// Max bytes per second per peer.
    pub max_bytes_per_sec: f64,
    /// Max pending validations per peer.
    pub max_pending_validations: usize,
    /// Score at or below which peer is quarantined.
    pub quarantine_threshold: i64,
    /// Score at or below which peer is banned.
    pub ban_threshold: i64,
    /// Decay interval.
    pub decay_interval: Duration,
    /// Whether to enable Prometheus metrics.
    pub enable_metrics: bool,
}

impl Default for PeerScoreConfig {
    fn default() -> Self {
        Self {
            max_msgs_per_sec: DEFAULT_PEER_MAX_MSGS_PER_SEC,
            max_bytes_per_sec: DEFAULT_PEER_MAX_BYTES_PER_SEC,
            max_pending_validations: DEFAULT_PEER_MAX_PENDING_VALIDATIONS,
            quarantine_threshold: DEFAULT_QUARANTINE_THRESHOLD,
            ban_threshold: DEFAULT_BAN_THRESHOLD,
            decay_interval: Duration::from_secs(DEFAULT_DECAY_INTERVAL_SECS),
            enable_metrics: false,
        }
    }
}

impl PeerScoreConfig {
    /// Validate the configuration.
    pub fn validate(&self) -> Result<(), String> {
        if self.max_msgs_per_sec <= 0.0 {
            return Err("max_msgs_per_sec must be > 0".into());
        }
        if self.max_bytes_per_sec <= 0.0 {
            return Err("max_bytes_per_sec must be > 0".into());
        }
        if self.max_pending_validations == 0 {
            return Err("max_pending_validations must be > 0".into());
        }
        if self.quarantine_threshold >= 0 {
            return Err("quarantine_threshold must be negative".into());
        }
        if self.ban_threshold >= 0 {
            return Err("ban_threshold must be negative".into());
        }
        if self.quarantine_threshold <= self.ban_threshold {
            return Err("quarantine_threshold must be greater than ban_threshold".into());
        }
        if self.decay_interval.is_zero() {
            return Err("decay_interval must be > 0".into());
        }
        Ok(())
    }
}

// -----------------------------------------------------------------------------
// Metrics
// -----------------------------------------------------------------------------

/// Prometheus metrics for peer scoring.
#[derive(Clone)]
pub struct PeerScoreMetrics {
    /// Total number of tracked peers.
    pub total_peers: Gauge,
    /// Number of quarantined peers.
    pub quarantined_peers: Gauge,
    /// Number of banned peers.
    pub banned_peers: Gauge,
    /// Total violations across all peers.
    pub total_violations: Counter,
    /// Total penalty events.
    pub penalties_total: Counter,
    /// Total reward events.
    pub rewards_total: Counter,
}

impl PeerScoreMetrics {
    /// Create and register metrics with the global Prometheus registry.
    pub fn new() -> Result<Self, prometheus::Error> {
        Ok(Self {
            total_peers: register_gauge!(
                "iona_peer_score_total_peers",
                "Total number of peers tracked by peer scoring"
            )?,
            quarantined_peers: register_gauge!(
                "iona_peer_score_quarantined_peers",
                "Number of quarantined peers"
            )?,
            banned_peers: register_gauge!(
                "iona_peer_score_banned_peers",
                "Number of banned peers"
            )?,
            total_violations: register_counter!(
                "iona_peer_score_total_violations",
                "Total violations recorded"
            )?,
            penalties_total: register_counter!(
                "iona_peer_score_penalties_total",
                "Total penalty events"
            )?,
            rewards_total: register_counter!(
                "iona_peer_score_rewards_total",
                "Total reward events"
            )?,
        })
    }

    /// Create an unregistered instance (for tests or disabled metrics).
    pub fn new_unregistered() -> Self {
        Self {
            total_peers: Gauge::new("iona_peer_score_total_peers", "Peers").unwrap(),
            quarantined_peers: Gauge::new("iona_peer_score_quarantined_peers", "Quarantined").unwrap(),
            banned_peers: Gauge::new("iona_peer_score_banned_peers", "Banned").unwrap(),
            total_violations: Counter::new("iona_peer_score_total_violations", "Violations").unwrap(),
            penalties_total: Counter::new("iona_peer_score_penalties_total", "Penalties").unwrap(),
            rewards_total: Counter::new("iona_peer_score_rewards_total", "Rewards").unwrap(),
        }
    }

    /// Update gauges from a snapshot.
    pub fn update(&self, snapshot: &PeerScoreSnapshot) {
        self.total_peers.set(snapshot.total_peers as f64);
        self.quarantined_peers.set(snapshot.quarantined as f64);
        self.banned_peers.set(snapshot.banned as f64);
        // total_violations is a counter; we set it by resetting and incrementing
        self.total_violations.reset();
        self.total_violations.inc_by(snapshot.total_violations as f64);
    }
}

// -----------------------------------------------------------------------------
// Violation reasons
// -----------------------------------------------------------------------------

/// Reason for penalising a peer, with a default penalty magnitude.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ViolationReason {
    /// Peer sent a message with a bad signature.
    BadSignature,
    /// Peer sent a message for an unknown topic.
    UnknownTopic,
    /// Peer sent a message on the wrong chain.
    WrongChainId,
    /// Peer exceeded the per-second message rate.
    MsgRateExceeded,
    /// Peer exceeded the per-second bandwidth quota.
    ByteRateExceeded,
    /// Peer disconnected mid request-response.
    IncompletResponse,
    /// Peer sent an invalid block.
    InvalidBlock,
    /// Peer sent duplicate evidence.
    DuplicateEvidence,
    /// Custom penalty with explicit magnitude.
    Custom,
}

impl ViolationReason {
    /// Default penalty magnitude for this violation.
    #[must_use]
    pub fn default_penalty(self) -> i64 {
        match self {
            Self::BadSignature => 20,
            Self::UnknownTopic => 5,
            Self::WrongChainId => 50,
            Self::MsgRateExceeded => 10,
            Self::ByteRateExceeded => 10,
            Self::IncompletResponse => 5,
            Self::InvalidBlock => 100,
            Self::DuplicateEvidence => 30,
            Self::Custom => 1,
        }
    }
}

// -----------------------------------------------------------------------------
// Token bucket (rate limiter)
// -----------------------------------------------------------------------------

/// Token bucket for rate limiting (messages or bytes).
#[derive(Debug)]
struct RateBucket {
    tokens: f64,
    max: f64,
    rate: f64, // tokens per second
    last: Instant,
}

impl RateBucket {
    fn new(rate_per_sec: f64) -> Self {
        Self {
            tokens: rate_per_sec,
            max: rate_per_sec,
            rate: rate_per_sec,
            last: Instant::now(),
        }
    }

    /// Try to consume `n` tokens. Returns `false` if quota exceeded.
    fn try_consume(&mut self, n: f64) -> bool {
        let now = Instant::now();
        let elapsed = now.duration_since(self.last).as_secs_f64();
        self.last = now;
        self.tokens = (self.tokens + elapsed * self.rate).min(self.max);
        if self.tokens >= n {
            self.tokens -= n;
            true
        } else {
            false
        }
    }
}

// -----------------------------------------------------------------------------
// Per-peer state
// -----------------------------------------------------------------------------

#[derive(Debug)]
struct PeerEntry {
    score: i64,
    msg_bucket: RateBucket,
    byte_bucket: RateBucket,
    pending_validations: usize,
    last_active: Instant,
    total_violations: u64,
}

impl PeerEntry {
    fn new(config: &PeerScoreConfig) -> Self {
        Self {
            score: 0,
            msg_bucket: RateBucket::new(config.max_msgs_per_sec),
            byte_bucket: RateBucket::new(config.max_bytes_per_sec),
            pending_validations: 0,
            last_active: Instant::now(),
            total_violations: 0,
        }
    }
}

// -----------------------------------------------------------------------------
// PeerScore (public API)
// -----------------------------------------------------------------------------

/// Per-peer scoring and quota enforcement.
///
/// Call `penalise` / `reward` from the swarm event loop.
/// Call `check_msg_quota` before enqueuing a message for validation.
/// Call `decay` periodically (e.g., every 10 seconds).
#[derive(Debug)]
pub struct PeerScore {
    peers: HashMap<String, PeerEntry>,
    last_decay: Instant,
    decay_every: Duration,
    ban_threshold: i64,
    quarantine_threshold: i64,
    max_pending_validations: usize,
    metrics: Option<Arc<PeerScoreMetrics>>,
}

impl PeerScore {
    /// Create a new peer scorer with custom configuration.
    pub fn new(config: PeerScoreConfig) -> Result<Self, String> {
        config.validate()?;
        let metrics = if config.enable_metrics {
            Some(Arc::new(PeerScoreMetrics::new().map_err(|e| e.to_string())?))
        } else {
            None
        };
        Ok(Self {
            peers: HashMap::new(),
            last_decay: Instant::now(),
            decay_every: config.decay_interval,
            ban_threshold: config.ban_threshold,
            quarantine_threshold: config.quarantine_threshold,
            max_pending_validations: config.max_pending_validations,
            metrics,
        })
    }

    /// Create a peer scorer with default configuration.
    #[must_use]
    pub fn with_defaults() -> Self {
        Self::new(PeerScoreConfig::default())
            .expect("default peer score config should be valid")
    }

    // -------------------------------------------------------------------------
    // Quota checks (call BEFORE expensive validation)
    // -------------------------------------------------------------------------

    /// Check if the peer is allowed to send another message (msg/s quota).
    /// Returns `true` if allowed, `false` if quota exceeded.
    pub fn check_msg_quota(&mut self, peer: &str) -> bool {
        let config = PeerScoreConfig {
            max_msgs_per_sec: DEFAULT_PEER_MAX_MSGS_PER_SEC,
            max_bytes_per_sec: DEFAULT_PEER_MAX_BYTES_PER_SEC,
            max_pending_validations: self.max_pending_validations,
            quarantine_threshold: self.quarantine_threshold,
            ban_threshold: self.ban_threshold,
            decay_interval: self.decay_every,
            enable_metrics: false, // not needed for entry creation
        };
        let entry = self
            .peers
            .entry(peer.to_string())
            .or_insert_with(|| PeerEntry::new(&config));
        entry.last_active = Instant::now();
        if entry.score <= self.ban_threshold {
            debug!(peer, score = entry.score, "peer banned, rejecting");
            return false;
        }
        let allowed = entry.msg_bucket.try_consume(1.0);
        if !allowed {
            entry.score = entry.score.saturating_sub(ViolationReason::MsgRateExceeded.default_penalty());
            entry.total_violations = entry.total_violations.saturating_add(1);
            if let Some(metrics) = &self.metrics {
                metrics.penalties_total.inc();
                self.update_metrics();
            }
            warn!(
                peer = %peer,
                score = entry.score,
                "p2p::score: msg rate exceeded"
            );
        }
        allowed
    }

    /// Check if the peer is allowed to send `bytes` more bytes (bytes/s quota).
    pub fn check_byte_quota(&mut self, peer: &str, bytes: usize) -> bool {
        let config = PeerScoreConfig {
            max_msgs_per_sec: DEFAULT_PEER_MAX_MSGS_PER_SEC,
            max_bytes_per_sec: DEFAULT_PEER_MAX_BYTES_PER_SEC,
            max_pending_validations: self.max_pending_validations,
            quarantine_threshold: self.quarantine_threshold,
            ban_threshold: self.ban_threshold,
            decay_interval: self.decay_every,
            enable_metrics: false,
        };
        let entry = self
            .peers
            .entry(peer.to_string())
            .or_insert_with(|| PeerEntry::new(&config));
        entry.last_active = Instant::now();
        if entry.score <= self.ban_threshold {
            debug!(peer, score = entry.score, "peer banned, rejecting");
            return false;
        }
        let allowed = entry.byte_bucket.try_consume(bytes as f64);
        if !allowed {
            entry.score = entry.score.saturating_sub(ViolationReason::ByteRateExceeded.default_penalty());
            entry.total_violations = entry.total_violations.saturating_add(1);
            if let Some(metrics) = &self.metrics {
                metrics.penalties_total.inc();
                self.update_metrics();
            }
            warn!(
                peer = %peer,
                bytes,
                score = entry.score,
                "p2p::score: byte rate exceeded"
            );
        }
        allowed
    }

    /// Acquire a pending-validation slot. Returns `false` if the peer is at
    /// `max_pending_validations`. The caller must call `release_validation`
    /// when validation completes (success or failure).
    pub fn acquire_validation_slot(&mut self, peer: &str) -> bool {
        let config = PeerScoreConfig {
            max_msgs_per_sec: DEFAULT_PEER_MAX_MSGS_PER_SEC,
            max_bytes_per_sec: DEFAULT_PEER_MAX_BYTES_PER_SEC,
            max_pending_validations: self.max_pending_validations,
            quarantine_threshold: self.quarantine_threshold,
            ban_threshold: self.ban_threshold,
            decay_interval: self.decay_every,
            enable_metrics: false,
        };
        let entry = self
            .peers
            .entry(peer.to_string())
            .or_insert_with(|| PeerEntry::new(&config));
        if entry.pending_validations >= self.max_pending_validations {
            warn!(
                peer = %peer,
                pending = entry.pending_validations,
                "p2p::score: max pending validations reached"
            );
            return false;
        }
        entry.pending_validations = entry.pending_validations.saturating_add(1);
        true
    }

    /// Release a pending-validation slot.
    pub fn release_validation_slot(&mut self, peer: &str) {
        if let Some(entry) = self.peers.get_mut(peer) {
            entry.pending_validations = entry.pending_validations.saturating_sub(1);
            debug!(peer, pending = entry.pending_validations, "validation slot released");
        }
    }

    // -------------------------------------------------------------------------
    // Score mutation
    // -------------------------------------------------------------------------

    /// Penalise a peer for a specific violation (using default penalty).
    pub fn penalise(&mut self, peer: &str, reason: ViolationReason) {
        self.penalise_with(peer, reason, reason.default_penalty());
    }

    /// Penalise a peer with a custom magnitude.
    pub fn penalise_with(&mut self, peer: &str, reason: ViolationReason, penalty: i64) {
        let config = PeerScoreConfig {
            max_msgs_per_sec: DEFAULT_PEER_MAX_MSGS_PER_SEC,
            max_bytes_per_sec: DEFAULT_PEER_MAX_BYTES_PER_SEC,
            max_pending_validations: self.max_pending_validations,
            quarantine_threshold: self.quarantine_threshold,
            ban_threshold: self.ban_threshold,
            decay_interval: self.decay_every,
            enable_metrics: false,
        };
        let entry = self
            .peers
            .entry(peer.to_string())
            .or_insert_with(|| PeerEntry::new(&config));
        entry.score = entry.score.saturating_sub(penalty.abs());
        entry.total_violations = entry.total_violations.saturating_add(1);
        if let Some(metrics) = &self.metrics {
            metrics.penalties_total.inc();
            self.update_metrics();
        }
        warn!(
            peer = %peer,
            score = entry.score,
            penalty,
            reason = ?reason,
            "p2p::score: peer penalised"
        );
    }

    /// Reward a peer for good behavior (valid block, helpful sync, etc.)
    pub fn reward(&mut self, peer: &str, amount: i64) {
        let config = PeerScoreConfig {
            max_msgs_per_sec: DEFAULT_PEER_MAX_MSGS_PER_SEC,
            max_bytes_per_sec: DEFAULT_PEER_MAX_BYTES_PER_SEC,
            max_pending_validations: self.max_pending_validations,
            quarantine_threshold: self.quarantine_threshold,
            ban_threshold: self.ban_threshold,
            decay_interval: self.decay_every,
            enable_metrics: false,
        };
        let entry = self
            .peers
            .entry(peer.to_string())
            .or_insert_with(|| PeerEntry::new(&config));
        // Cap score at 0 to prevent score farming.
        entry.score = (entry.score + amount.abs()).min(0);
        if let Some(metrics) = &self.metrics {
            metrics.rewards_total.inc();
            self.update_metrics();
        }
        debug!(peer, score = entry.score, amount, "p2p::score: peer rewarded");
    }

    // -------------------------------------------------------------------------
    // Legacy helpers (backward compat)
    // -------------------------------------------------------------------------

    /// Legacy method: note a bad behaviour with a custom penalty.
    pub fn note_bad(&mut self, peer: impl Into<String>, penalty: i64) {
        self.penalise_with(&peer.into(), ViolationReason::Custom, penalty);
    }

    /// Legacy method: note good behaviour with a reward.
    pub fn note_good(&mut self, peer: impl Into<String>, reward: i64) {
        self.reward(&peer.into(), reward);
    }

    // -------------------------------------------------------------------------
    // Status queries
    // -------------------------------------------------------------------------

    /// Get the current score of a peer.
    #[must_use]
    pub fn score(&self, peer: &str) -> i64 {
        self.peers.get(peer).map(|e| e.score).unwrap_or(0)
    }

    /// Check if a peer should be permanently banned.
    #[must_use]
    pub fn should_ban(&self, peer: &str) -> bool {
        self.peers
            .get(peer)
            .map(|e| e.score <= self.ban_threshold)
            .unwrap_or(false)
    }

    /// Check if a peer should be quarantined (temporary isolation).
    #[must_use]
    pub fn should_quarantine(&self, peer: &str) -> bool {
        self.peers
            .get(peer)
            .map(|e| e.score <= self.quarantine_threshold && e.score > self.ban_threshold)
            .unwrap_or(false)
    }

    /// Check if a peer is blocked (quarantined or banned).
    #[must_use]
    pub fn is_blocked(&self, peer: &str) -> bool {
        self.peers
            .get(peer)
            .map(|e| e.score <= self.quarantine_threshold)
            .unwrap_or(false)
    }

    /// Number of pending validation slots currently used by a peer.
    #[must_use]
    pub fn pending_validations(&self, peer: &str) -> usize {
        self.peers
            .get(peer)
            .map(|e| e.pending_validations)
            .unwrap_or(0)
    }

    /// Get the total number of tracked peers.
    #[must_use]
    pub fn total_peers(&self) -> usize {
        self.peers.len()
    }

    // -------------------------------------------------------------------------
    // Snapshot for metrics
    // -------------------------------------------------------------------------

    /// Capture a snapshot of current peer scores for metrics export.
    #[must_use]
    pub fn snapshot(&self) -> PeerScoreSnapshot {
        let quarantined = self
            .peers
            .values()
            .filter(|e| e.score <= self.quarantine_threshold && e.score > self.ban_threshold)
            .count();
        let banned = self
            .peers
            .values()
            .filter(|e| e.score <= self.ban_threshold)
            .count();
        let total_violations: u64 = self.peers.values().map(|e| e.total_violations).sum();
        PeerScoreSnapshot {
            quarantined,
            banned,
            total_peers: self.peers.len(),
            total_violations,
        }
    }

    // -------------------------------------------------------------------------
    // Score decay (call periodically)
    // -------------------------------------------------------------------------

    /// Apply score decay to all peers (move scores toward zero).
    /// Should be called regularly (e.g., every 10 seconds).
    pub fn decay(&mut self) {
        if self.last_decay.elapsed() < self.decay_every {
            return;
        }
        self.last_decay = Instant::now();
        let mut decayed = 0;
        for entry in self.peers.values_mut() {
            if entry.score < 0 {
                let old = entry.score;
                entry.score = (entry.score * DECAY_FACTOR) / DECAY_DIVISOR;
                if entry.score != old {
                    decayed += 1;
                }
            }
        }

        // Evict very old inactive peers (10 min idle, not banned).
        let cutoff = Duration::from_secs(600);
        let removed = self
            .peers
            .extract_if(|_, e| e.score > self.ban_threshold && e.last_active.elapsed() > cutoff)
            .count();

        if decayed > 0 || removed > 0 {
            debug!(decayed, removed, "peer score decay applied");
        }
        if let Some(metrics) = &self.metrics {
            self.update_metrics();
        }
    }

    /// Update metrics from current snapshot (called internally).
    fn update_metrics(&self) {
        if let Some(metrics) = &self.metrics {
            let snap = self.snapshot();
            metrics.update(&snap);
        }
    }
}

// -----------------------------------------------------------------------------
// Snapshot structure
// -----------------------------------------------------------------------------

/// Snapshot of peer score statistics (for metrics).
#[derive(Debug, Clone)]
pub struct PeerScoreSnapshot {
    pub quarantined: usize,
    pub banned: usize,
    pub total_peers: usize,
    pub total_violations: u64,
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_msg_rate_quota_allows_burst() {
        let mut ps = PeerScore::with_defaults();
        let max = DEFAULT_PEER_MAX_MSGS_PER_SEC as usize;
        for _ in 0..max {
            assert!(ps.check_msg_quota("peer1"), "expected allowed");
        }
    }

    #[test]
    fn test_msg_rate_quota_rejects_after_burst() {
        let mut ps = PeerScore::with_defaults();
        let max = DEFAULT_PEER_MAX_MSGS_PER_SEC as usize;
        for _ in 0..max {
            ps.check_msg_quota("peer1");
        }
        assert!(!ps.check_msg_quota("peer1"), "expected rate-limited");
    }

    #[test]
    fn test_byte_quota_rejects_large_message() {
        let mut ps = PeerScore::with_defaults();
        let too_big = DEFAULT_PEER_MAX_BYTES_PER_SEC as usize + 1;
        assert!(!ps.check_byte_quota("peer1", too_big));
    }

    #[test]
    fn test_pending_validation_cap() {
        let mut ps = PeerScore::with_defaults();
        for _ in 0..DEFAULT_PEER_MAX_PENDING_VALIDATIONS {
            assert!(ps.acquire_validation_slot("peer1"));
        }
        assert!(!ps.acquire_validation_slot("peer1"));
        ps.release_validation_slot("peer1");
        assert!(ps.acquire_validation_slot("peer1"));
    }

    #[test]
    fn test_ban_threshold_blocks_all_traffic() {
        let mut ps = PeerScore::with_defaults();
        ps.penalise_with(
            "peer1",
            ViolationReason::InvalidBlock,
            DEFAULT_BAN_THRESHOLD.unsigned_abs() as i64 + 10,
        );
        assert!(ps.should_ban("peer1"));
        assert!(!ps.check_msg_quota("peer1"));
        assert!(!ps.check_byte_quota("peer1", 1));
    }

    #[test]
    fn test_quarantine_threshold() {
        let mut ps = PeerScore::with_defaults();
        ps.penalise_with(
            "peer1",
            ViolationReason::BadSignature,
            DEFAULT_QUARANTINE_THRESHOLD.unsigned_abs() as i64 + 5,
        );
        assert!(
            ps.should_quarantine("peer1") || ps.should_ban("peer1"),
            "score {} should trigger quarantine or ban",
            ps.score("peer1")
        );
    }

    #[test]
    fn test_score_decay() {
        let mut config = PeerScoreConfig::default();
        config.decay_interval = Duration::from_millis(1);
        let mut ps = PeerScore::new(config).unwrap();
        ps.penalise_with("peer1", ViolationReason::Custom, 100);
        let before = ps.score("peer1");
        std::thread::sleep(Duration::from_millis(2));
        ps.decay();
        let after = ps.score("peer1");
        assert!(
            after > before,
            "score should improve after decay: before={before} after={after}"
        );
    }

    #[test]
    fn test_different_peers_are_independent() {
        let mut ps = PeerScore::with_defaults();
        let max = DEFAULT_PEER_MAX_MSGS_PER_SEC as usize;
        for _ in 0..max {
            ps.check_msg_quota("peer1");
        }
        assert!(!ps.check_msg_quota("peer1"));
        assert!(ps.check_msg_quota("peer2"));
    }

    #[test]
    fn test_snapshot() {
        let mut ps = PeerScore::with_defaults();
        ps.penalise_with("peer1", ViolationReason::InvalidBlock, 300); // ban
        ps.penalise_with("peer2", ViolationReason::BadSignature, 60); // quarantine
        let snap = ps.snapshot();
        assert_eq!(snap.banned, 1);
        assert_eq!(snap.quarantined, 1);
        assert_eq!(snap.total_peers, 2);
    }

    #[test]
    fn test_total_peers() {
        let mut ps = PeerScore::with_defaults();
        assert_eq!(ps.total_peers(), 0);
        ps.check_msg_quota("peer1");
        assert_eq!(ps.total_peers(), 1);
        ps.check_msg_quota("peer2");
        assert_eq!(ps.total_peers(), 2);
    }

    #[test]
    fn test_config_validation() {
        let mut cfg = PeerScoreConfig::default();
        assert!(cfg.validate().is_ok());

        cfg.max_msgs_per_sec = 0.0;
        assert!(cfg.validate().is_err());

        cfg.max_msgs_per_sec = 60.0;
        cfg.quarantine_threshold = -10;
        cfg.ban_threshold = -20; // quarantine > ban? No, -10 > -20, valid
        assert!(cfg.validate().is_ok());

        cfg.quarantine_threshold = -30;
        cfg.ban_threshold = -20; // -30 <= -20, invalid
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn test_metrics_integration() {
        let mut config = PeerScoreConfig::default();
        config.enable_metrics = true;
        let mut ps = PeerScore::new(config).unwrap();
        ps.penalise("peer1", ViolationReason::BadSignature);
        ps.reward("peer2", 5);
        let snap = ps.snapshot();
        assert!(snap.total_violations > 0);
        // We can't inspect metrics directly without registry, but ensure no panic.
    }
}
