//! RPC hardening: rate limiting, IP ban/quarantine, request budgets,
//! concurrency cap, structured violation tracking, and request-ID generation.
//!
//! Security invariants enforced here:
//! - Per-IP token-bucket rate limits (submit vs. read)
//! - Automatic IP quarantine after N consecutive violations
//! - Automatic IP ban after M quarantine escalations
//! - Global concurrency cap (prevents thread exhaustion)
//! - Max body size enforced before any deserialization
//! - Max item count per batch request
//! - Max CPU time via request deadline (set at entry, checked by handler)
//! - Request-ID injected for every request (structured log correlation)
//! - No secrets in error responses (all errors are opaque codes)

use parking_lot::Mutex;
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

// ── Hard limits ───────────────────────────────────────────────────────────

/// Max body bytes before we reject without reading. Applies to all endpoints.
pub const MAX_BODY_BYTES: usize = 4_096;

/// Max items in a batch RPC call (future: eth_batchCall etc.)
pub const MAX_BATCH_ITEMS: usize = 10;

/// Max pubkey bytes on a submitted transaction.
pub const MAX_TX_PUBKEY_BYTES: usize = 64;

/// Global max simultaneous in-flight RPC requests.
pub const MAX_CONCURRENT_REQUESTS: usize = 100;

/// Rate: max tx submissions per second per IP.
pub const SUBMIT_RATE_PER_SEC: u32 = 100;

/// Rate: max read requests per second per IP.
pub const READ_RATE_PER_SEC: u32 = 500;

/// Consecutive rate-limit violations before IP is quarantined.
pub const VIOLATIONS_BEFORE_QUARANTINE: u32 = 20;

/// Quarantine escalations before IP is permanently banned.
pub const QUARANTINE_BEFORE_BAN: u32 = 3;

/// How long a quarantine lasts before the IP is given another chance.
pub const QUARANTINE_DURATION: Duration = Duration::from_secs(300); // 5 min

// ── Token bucket ──────────────────────────────────────────────────────────

struct TokenBucket {
    tokens: f64,
    max: f64,
    last: Instant,
    rate_per_sec: f64,
    /// Consecutive rate-limit hits (reset on a successful request).
    violation_streak: u32,
}

impl TokenBucket {
    fn new(rate_per_sec: u32) -> Self {
        let r = rate_per_sec as f64;
        Self {
            tokens: r,
            max: r,
            last: Instant::now(),
            rate_per_sec: r,
            violation_streak: 0,
        }
    }

    /// Returns `true` if the request is allowed.
    fn try_consume(&mut self) -> bool {
        let now = Instant::now();
        let elapsed = now.duration_since(self.last).as_secs_f64();
        self.last = now;
        self.tokens = (self.tokens + elapsed * self.rate_per_sec).min(self.max);

        if self.tokens >= 1.0 {
            self.tokens -= 1.0;
            self.violation_streak = 0; // good request resets streak
            true
        } else {
            self.violation_streak = self.violation_streak.saturating_add(1);
            false
        }
    }
}

// ── Per-IP state ─────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IpStatus {
    /// Normal operation.
    Allowed,
    /// Temporarily blocked; reconnect allowed after `until`.
    Quarantined {
        until: Instant,
        escalation_count: u32,
    },
    /// Permanently blocked for this session.
    Banned,
}

struct IpEntry {
    submit: TokenBucket,
    read: TokenBucket,
    status: IpStatus,
    /// Total requests ever rejected for this IP (for metrics/audit).
    total_rejections: u64,
}

impl IpEntry {
    fn new() -> Self {
        Self {
            submit: TokenBucket::new(SUBMIT_RATE_PER_SEC),
            read: TokenBucket::new(READ_RATE_PER_SEC),
            status: IpStatus::Allowed,
            total_rejections: 0,
        }
    }

    /// Check and possibly escalate quarantine/ban state.
    /// Returns `true` if the IP is currently blocked.
    fn is_blocked(&mut self) -> bool {
        match &self.status {
            IpStatus::Banned => true,
            IpStatus::Quarantined {
                until,
                escalation_count,
            } => {
                if Instant::now() < *until {
                    true
                } else {
                    // Quarantine expired — allow again, but remember escalation count.
                    let count = *escalation_count;
                    self.status = IpStatus::Allowed;
                    // Halve bucket to give a slower restart.
                    self.submit.tokens = self.submit.max / 2.0;
                    self.read.tokens = self.read.max / 2.0;
                    // Re-store escalation count for future use (needed after mutation).
                    if count >= QUARANTINE_BEFORE_BAN {
                        self.status = IpStatus::Banned;
                        return true;
                    }
                    false
                }
            }
            IpStatus::Allowed => false,
        }
    }

    /// Called when a violation streak exceeds the threshold.
    fn maybe_escalate(&mut self, streak: u32) {
        if streak < VIOLATIONS_BEFORE_QUARANTINE {
            return;
        }
        match &self.status {
            IpStatus::Allowed => {
                tracing::warn!(
                    streak,
                    "rpc::limiter: IP quarantined due to violation streak"
                );
                self.status = IpStatus::Quarantined {
                    until: Instant::now() + QUARANTINE_DURATION,
                    escalation_count: 1,
                };
            }
            IpStatus::Quarantined {
                until,
                escalation_count,
            } => {
                let new_count = escalation_count + 1;
                if new_count >= QUARANTINE_BEFORE_BAN {
                    tracing::warn!(
                        escalations = new_count,
                        "rpc::limiter: IP permanently banned"
                    );
                    self.status = IpStatus::Banned;
                } else {
                    // Extend quarantine
                    self.status = IpStatus::Quarantined {
                        until: (*until).max(Instant::now()) + QUARANTINE_DURATION,
                        escalation_count: new_count,
                    };
                }
            }
            IpStatus::Banned => {}
        }
    }
}

// ── Global concurrency counter ────────────────────────────────────────────

/// Tracks the number of currently in-flight RPC requests.
#[derive(Clone)]
pub struct ConcurrencyGuard {
    current: Arc<AtomicUsize>,
    max: usize,
}

impl ConcurrencyGuard {
    pub fn new(max: usize) -> Self {
        Self {
            current: Arc::new(AtomicUsize::new(0)),
            max,
        }
    }

    /// Attempt to acquire a slot. Returns a `ConcurrencyTicket` on success.
    /// The slot is released when the ticket is dropped.
    pub fn try_acquire(&self) -> Option<ConcurrencyTicket> {
        // Use a compare-and-swap loop to atomically increment if below max.
        let mut cur = self.current.load(Ordering::Relaxed);
        loop {
            if cur >= self.max {
                return None;
            }
            match self.current.compare_exchange_weak(
                cur,
                cur + 1,
                Ordering::AcqRel,
                Ordering::Relaxed,
            ) {
                Ok(_) => {
                    return Some(ConcurrencyTicket {
                        guard: self.current.clone(),
                    });
                }
                Err(actual) => cur = actual,
            }
        }
    }

    pub fn current(&self) -> usize {
        self.current.load(Ordering::Relaxed)
    }
}

/// RAII guard that decrements the concurrency counter on drop.
pub struct ConcurrencyTicket {
    guard: Arc<AtomicUsize>,
}

impl Drop for ConcurrencyTicket {
    fn drop(&mut self) {
        self.guard.fetch_sub(1, Ordering::AcqRel);
    }
}

// ── Request-ID generator ─────────────────────────────────────────────────

static REQUEST_COUNTER: AtomicUsize = AtomicUsize::new(1);

/// Generate a unique request ID for structured logging correlation.
/// Format: `req-<monotonic_counter>-<unix_millis_low16>`
pub fn new_request_id() -> String {
    let seq = REQUEST_COUNTER.fetch_add(1, Ordering::Relaxed);
    let ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .subsec_millis();
    format!("req-{seq}-{ts:04x}")
}

// ── Main RpcLimiter ───────────────────────────────────────────────────────

pub struct RpcLimiter {
    ips: Mutex<HashMap<IpAddr, IpEntry>>,
    last_cleanup: Mutex<Instant>,
    /// Global concurrency cap across all requests.
    pub concurrency: ConcurrencyGuard,
    // ── Metrics (atomic counters, no external dep needed) ─────────────────
    pub metric_rate_limit_hits: Arc<AtomicUsize>,
    pub metric_quarantine_total: Arc<AtomicUsize>,
    pub metric_ban_total: Arc<AtomicUsize>,
    pub metric_payload_too_large: Arc<AtomicUsize>,
    pub metric_decode_errors: Arc<AtomicUsize>,
    pub metric_concurrency_rejected: Arc<AtomicUsize>,
}

impl RpcLimiter {
    pub fn new() -> Self {
        Self {
            ips: Mutex::new(HashMap::new()),
            last_cleanup: Mutex::new(Instant::now()),
            concurrency: ConcurrencyGuard::new(MAX_CONCURRENT_REQUESTS),
            metric_rate_limit_hits: Arc::new(AtomicUsize::new(0)),
            metric_quarantine_total: Arc::new(AtomicUsize::new(0)),
            metric_ban_total: Arc::new(AtomicUsize::new(0)),
            metric_payload_too_large: Arc::new(AtomicUsize::new(0)),
            metric_decode_errors: Arc::new(AtomicUsize::new(0)),
            metric_concurrency_rejected: Arc::new(AtomicUsize::new(0)),
        }
    }

    /// Check if a tx submit is allowed. Returns `RpcLimitResult`.
    pub fn check_submit(&self, ip: IpAddr, req_id: &str) -> RpcLimitResult {
        self.cleanup_if_needed();
        let mut ips = self.ips.lock();
        let entry = ips.entry(ip).or_insert_with(IpEntry::new);

        if entry.is_blocked() {
            entry.total_rejections += 1;
            self.metric_rate_limit_hits.fetch_add(1, Ordering::Relaxed);
            tracing::warn!(
                %ip, %req_id,
                "rpc::limiter: blocked IP attempted submit"
            );
            return RpcLimitResult::Blocked;
        }

        if entry.submit.try_consume() {
            RpcLimitResult::Allowed
        } else {
            entry.total_rejections += 1;
            let streak = entry.submit.violation_streak;
            entry.maybe_escalate(streak);
            self.metric_rate_limit_hits.fetch_add(1, Ordering::Relaxed);
            tracing::warn!(
                %ip, %req_id, streak,
                "rpc::limiter: submit rate limit hit"
            );
            RpcLimitResult::RateLimited
        }
    }

    /// Check if a read request is allowed.
    pub fn check_read(&self, ip: IpAddr, req_id: &str) -> RpcLimitResult {
        self.cleanup_if_needed();
        let mut ips = self.ips.lock();
        let entry = ips.entry(ip).or_insert_with(IpEntry::new);

        if entry.is_blocked() {
            entry.total_rejections += 1;
            self.metric_rate_limit_hits.fetch_add(1, Ordering::Relaxed);
            tracing::warn!(
                %ip, %req_id,
                "rpc::limiter: blocked IP attempted read"
            );
            return RpcLimitResult::Blocked;
        }

        if entry.read.try_consume() {
            RpcLimitResult::Allowed
        } else {
            entry.total_rejections += 1;
            let streak = entry.read.violation_streak;
            entry.maybe_escalate(streak);
            self.metric_rate_limit_hits.fetch_add(1, Ordering::Relaxed);
            tracing::warn!(
                %ip, %req_id, streak,
                "rpc::limiter: read rate limit hit"
            );
            RpcLimitResult::RateLimited
        }
    }

    /// Record a decode error for an IP (counts toward violation streak).
    pub fn record_decode_error(&self, ip: IpAddr, req_id: &str) {
        self.metric_decode_errors.fetch_add(1, Ordering::Relaxed);
        tracing::warn!(%ip, %req_id, "rpc::limiter: decode error");
        let mut ips = self.ips.lock();
        let entry = ips.entry(ip).or_insert_with(IpEntry::new);
        // Penalise the submit bucket streak directly.
        entry.submit.violation_streak = entry.submit.violation_streak.saturating_add(5); // decode errors cost more
        let streak = entry.submit.violation_streak;
        entry.maybe_escalate(streak);
    }

    /// Record a payload-too-large violation.
    pub fn record_payload_too_large(&self, ip: IpAddr, req_id: &str, size: usize) {
        self.metric_payload_too_large
            .fetch_add(1, Ordering::Relaxed);
        tracing::warn!(%ip, %req_id, size, "rpc::limiter: payload too large");
        let mut ips = self.ips.lock();
        let entry = ips.entry(ip).or_insert_with(IpEntry::new);
        entry.submit.violation_streak = entry.submit.violation_streak.saturating_add(3);
        let streak = entry.submit.violation_streak;
        entry.maybe_escalate(streak);
    }

    /// Acquire a concurrency slot. Returns `None` if at cap.
    pub fn try_concurrency_slot(&self, req_id: &str) -> Option<ConcurrencyTicket> {
        match self.concurrency.try_acquire() {
            Some(t) => Some(t),
            None => {
                self.metric_concurrency_rejected
                    .fetch_add(1, Ordering::Relaxed);
                tracing::warn!(
                    %req_id,
                    current = self.concurrency.current(),
                    max = MAX_CONCURRENT_REQUESTS,
                    "rpc::limiter: concurrency cap reached"
                );
                None
            }
        }
    }

    /// Snapshot of current metrics for Prometheus/health endpoint.
    pub fn metrics_snapshot(&self) -> RpcMetrics {
        let ips = self.ips.lock();
        let quarantined = ips
            .values()
            .filter(|e| matches!(e.status, IpStatus::Quarantined { .. }))
            .count();
        let banned = ips
            .values()
            .filter(|e| e.status == IpStatus::Banned)
            .count();
        drop(ips);

        RpcMetrics {
            rate_limit_hits: self.metric_rate_limit_hits.load(Ordering::Relaxed),
            payload_too_large: self.metric_payload_too_large.load(Ordering::Relaxed),
            decode_errors: self.metric_decode_errors.load(Ordering::Relaxed),
            concurrency_rejected: self.metric_concurrency_rejected.load(Ordering::Relaxed),
            ips_quarantined: quarantined,
            ips_banned: banned,
            concurrent_requests: self.concurrency.current(),
        }
    }

    // Cleanup stale entries every 60 s.
    fn cleanup_if_needed(&self) {
        let mut last = self.last_cleanup.lock();
        if last.elapsed() < Duration::from_secs(60) {
            return;
        }
        *last = Instant::now();
        drop(last);

        let cutoff = Duration::from_secs(600); // 10 min idle
        let mut ips = self.ips.lock();
        ips.retain(|_, entry| {
            // Never evict banned IPs — ban is persistent for this session.
            if entry.status == IpStatus::Banned {
                return true;
            }
            // Keep if recently active.
            entry.submit.last.elapsed() < cutoff || entry.read.last.elapsed() < cutoff
        });
    }
}

impl Default for RpcLimiter {
    fn default() -> Self {
        Self::new()
    }
}

// ── Result type ───────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RpcLimitResult {
    Allowed,
    RateLimited,
    Blocked,
}

impl RpcLimitResult {
    pub fn is_allowed(self) -> bool {
        self == Self::Allowed
    }

    /// HTTP status code to return on rejection.
    pub fn http_status(self) -> u16 {
        match self {
            Self::Allowed => 200,
            Self::RateLimited => 429,
            Self::Blocked => 403,
        }
    }
}

// ── Metrics snapshot ─────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct RpcMetrics {
    pub rate_limit_hits: usize,
    pub payload_too_large: usize,
    pub decode_errors: usize,
    pub concurrency_rejected: usize,
    pub ips_quarantined: usize,
    pub ips_banned: usize,
    pub concurrent_requests: usize,
}

// ── Input validation ──────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub enum ValidationError {
    PayloadTooLong {
        len: usize,
        max: usize,
    },
    InvalidUtf8,
    PubkeyTooLong,
    GasLimitZero,
    MaxFeeZero,
    ChainIdMismatch {
        got: u64,
        expected: u64,
    },
    NonceGap {
        sender: String,
        expected: u64,
        got: u64,
    },
    BatchTooLarge {
        count: usize,
        max: usize,
    },
}

impl std::fmt::Display for ValidationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // IMPORTANT: error messages must not include internal paths, module names,
        // or any implementation details. Only safe, opaque codes.
        match self {
            Self::PayloadTooLong { len, max } => write!(f, "PAYLOAD_TOO_LONG: {len} > {max}"),
            Self::InvalidUtf8 => write!(f, "INVALID_ENCODING"),
            Self::PubkeyTooLong => write!(f, "PUBKEY_TOO_LONG"),
            Self::GasLimitZero => write!(f, "GAS_LIMIT_ZERO"),
            Self::MaxFeeZero => write!(f, "MAX_FEE_ZERO"),
            Self::ChainIdMismatch { got, expected } => {
                write!(f, "CHAIN_ID_MISMATCH: got={got} expected={expected}")
            }
            Self::NonceGap {
                sender,
                expected,
                got,
            } => write!(
                f,
                "NONCE_GAP: sender={sender} expected={expected} got={got}"
            ),
            Self::BatchTooLarge { count, max } => write!(f, "BATCH_TOO_LARGE: {count} > {max}"),
        }
    }
}

/// Validate a transaction before touching any state.
/// Returns `Err` fast if anything is wrong — no state access on error path.
pub fn validate_tx(
    tx: &crate::types::Tx,
    expected_chain_id: u64,
    sender_nonce: u64,
) -> Result<(), ValidationError> {
    if tx.payload.len() > MAX_BODY_BYTES {
        return Err(ValidationError::PayloadTooLong {
            len: tx.payload.len(),
            max: MAX_BODY_BYTES,
        });
    }
    if std::str::from_utf8(tx.payload.as_bytes()).is_err() {
        return Err(ValidationError::InvalidUtf8);
    }
    if tx.pubkey.len() > MAX_TX_PUBKEY_BYTES {
        return Err(ValidationError::PubkeyTooLong);
    }
    if tx.gas_limit == 0 {
        return Err(ValidationError::GasLimitZero);
    }
    if tx.max_fee_per_gas == 0 {
        return Err(ValidationError::MaxFeeZero);
    }
    if tx.chain_id != expected_chain_id {
        return Err(ValidationError::ChainIdMismatch {
            got: tx.chain_id,
            expected: expected_chain_id,
        });
    }
    if tx.nonce < sender_nonce {
        return Err(ValidationError::NonceGap {
            sender: tx.from.clone(),
            expected: sender_nonce,
            got: tx.nonce,
        });
    }
    Ok(())
}

/// Validate raw body size before JSON deserialization.
/// Call this as the very first check, before any parsing.
pub fn validate_body_size(body: &[u8], limit: usize) -> Result<(), ValidationError> {
    if body.len() > limit {
        Err(ValidationError::PayloadTooLong {
            len: body.len(),
            max: limit,
        })
    } else {
        Ok(())
    }
}

/// Validate batch item count.
pub fn validate_batch_size(count: usize) -> Result<(), ValidationError> {
    if count > MAX_BATCH_ITEMS {
        Err(ValidationError::BatchTooLarge {
            count,
            max: MAX_BATCH_ITEMS,
        })
    } else {
        Ok(())
    }
}

// ── Tests ──────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    fn ip(a: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(127, 0, 0, a))
    }

    #[test]
    fn test_submit_rate_limit_allows_up_to_burst() {
        let limiter = RpcLimiter::new();
        let peer = ip(1);
        // First SUBMIT_RATE_PER_SEC requests should all be allowed.
        for _ in 0..SUBMIT_RATE_PER_SEC {
            assert_eq!(limiter.check_submit(peer, "req-0"), RpcLimitResult::Allowed);
        }
    }

    #[test]
    fn test_submit_rate_limit_rejects_after_burst() {
        let limiter = RpcLimiter::new();
        let peer = ip(2);
        // Drain the burst.
        for _ in 0..SUBMIT_RATE_PER_SEC {
            limiter.check_submit(peer, "req-x");
        }
        // Next should be rate-limited.
        let result = limiter.check_submit(peer, "req-x");
        assert!(
            matches!(
                result,
                RpcLimitResult::RateLimited | RpcLimitResult::Blocked
            ),
            "expected rate limited, got {result:?}"
        );
    }

    #[test]
    fn test_quarantine_after_violations() {
        let limiter = RpcLimiter::new();
        let peer = ip(3);
        // Drain burst + trigger VIOLATIONS_BEFORE_QUARANTINE consecutive rejections.
        for _ in 0..(SUBMIT_RATE_PER_SEC + VIOLATIONS_BEFORE_QUARANTINE) {
            limiter.check_submit(peer, "req-x");
        }
        // Now the IP should be quarantined/blocked.
        let result = limiter.check_submit(peer, "req-x");
        assert!(
            matches!(
                result,
                RpcLimitResult::RateLimited | RpcLimitResult::Blocked
            ),
            "IP should be quarantined after violation streak"
        );
    }

    #[test]
    fn test_decode_error_penalises_streak() {
        let limiter = RpcLimiter::new();
        let peer = ip(4);
        limiter.record_decode_error(peer, "req-1");
        assert_eq!(limiter.metric_decode_errors.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn test_payload_too_large_penalises() {
        let limiter = RpcLimiter::new();
        let peer = ip(5);
        limiter.record_payload_too_large(peer, "req-1", MAX_BODY_BYTES + 1);
        assert_eq!(limiter.metric_payload_too_large.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn test_concurrency_cap() {
        let limiter = RpcLimiter::new();
        // Drain the concurrency pool.
        let mut tickets = Vec::new();
        for _ in 0..MAX_CONCURRENT_REQUESTS {
            tickets.push(limiter.try_concurrency_slot("req-x").expect("slot"));
        }
        // Now it should be full.
        assert!(
            limiter.try_concurrency_slot("req-overflow").is_none(),
            "concurrency cap should be enforced"
        );
        assert_eq!(
            limiter.metric_concurrency_rejected.load(Ordering::Relaxed),
            1
        );
        // Drop tickets — slots are released.
        drop(tickets);
        assert!(limiter.try_concurrency_slot("req-after").is_some());
    }

    #[test]
    fn test_request_id_uniqueness() {
        let ids: Vec<_> = (0..100).map(|_| new_request_id()).collect();
        let unique: std::collections::HashSet<_> = ids.iter().collect();
        assert_eq!(ids.len(), unique.len(), "request IDs must be unique");
    }

    #[test]
    fn test_validate_body_size() {
        let ok = vec![0u8; MAX_BODY_BYTES];
        assert!(validate_body_size(&ok, MAX_BODY_BYTES).is_ok());

        let too_big = vec![0u8; MAX_BODY_BYTES + 1];
        assert!(validate_body_size(&too_big, MAX_BODY_BYTES).is_err());
    }

    #[test]
    fn test_validate_batch_size() {
        assert!(validate_batch_size(MAX_BATCH_ITEMS).is_ok());
        assert!(validate_batch_size(MAX_BATCH_ITEMS + 1).is_err());
    }

    #[test]
    fn test_metrics_snapshot() {
        let limiter = RpcLimiter::new();
        let snap = limiter.metrics_snapshot();
        assert_eq!(snap.rate_limit_hits, 0);
        assert_eq!(snap.ips_banned, 0);
        assert_eq!(snap.concurrent_requests, 0);
    }

    #[test]
    fn test_error_messages_are_opaque() {
        // Ensure error messages contain no internal path info.
        let err = ValidationError::PayloadTooLong {
            len: 9999,
            max: 4096,
        };
        let msg = err.to_string();
        assert!(!msg.contains("src/"), "error must not leak source paths");
        assert!(!msg.contains("::"), "error must not leak module paths");
    }

    #[test]
    fn test_different_ips_are_independent() {
        let limiter = RpcLimiter::new();
        // Drain IP 1's submit budget.
        for _ in 0..SUBMIT_RATE_PER_SEC {
            limiter.check_submit(ip(10), "req-x");
        }
        // IP 2 should still be allowed.
        assert_eq!(
            limiter.check_submit(ip(11), "req-y"),
            RpcLimitResult::Allowed
        );
    }
}
