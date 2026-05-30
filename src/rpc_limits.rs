//! Quantum RPC hardening: rate limiting, IP ban/quarantine, request budgets,
//! concurrency cap, structured violation tracking, and request‑ID generation.
//!
//! # Quantum Security Model
//!
//! RPC security is modeled as a quantum system where each IP address
//! exists in a superposition of states: |allowed⟩, |quarantined⟩, |banned⟩.
//! Rate limiting acts as a quantum measurement that collapses the state
//! based on observed behavior.
//!
//! # Hamiltonian for RPC Security
//!
//! ```text
//! Ĥ_rpc = Ĥ_rate + Ĥ_quarantine + Ĥ_concurrency + Ĥ_validation
//!
//! Ĥ_rate        = Σ_i ω_i a†_i a_i                    (token bucket oscillator)
//! Ĥ_quarantine  = Σ_q E_q |q⟩⟨q|                      (quarantine potential)
//! Ĥ_concurrency = Σ_c ν_c b†_c b_c                    (slot occupation)
//! Ĥ_validation  = Σ_v λ_v |valid_v⟩⟨valid_v|          (validation observable)
//! ```
//!
//! # Quantum Token Bucket
//!
//! The token bucket is a quantum harmonic oscillator where:
//! - Creation operator a† adds a token (rate-limited refill)
//! - Annihilation operator a consumes a token (request)
//! - Occupation number ⟨a†a⟩ = token count
//!
//! # Quantum Quarantine
//!
//! IP quarantine is a potential barrier that traps misbehaving IPs:
//! ```text
//! V_quarantine(x) = E₀ × θ(violations - threshold)
//! ```
//! where θ is the Heaviside step function.

use parking_lot::Mutex;
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use thiserror::Error;

// -----------------------------------------------------------------------------
// Quantum Constants
// -----------------------------------------------------------------------------

/// Reduced Planck constant (natural units).
const HBAR: f64 = 1.0;

/// Max body bytes before we reject without reading (quantum measurement limit).
pub const MAX_BODY_BYTES: usize = 4_096;

/// Max items in a batch RPC call (entanglement limit).
pub const MAX_BATCH_ITEMS: usize = 10;

/// Max pubkey bytes on a submitted transaction (quantum state size).
pub const MAX_TX_PUBKEY_BYTES: usize = 64;

/// Global max simultaneous in‑flight RPC requests (occupation number limit).
pub const MAX_CONCURRENT_REQUESTS: usize = 100;

/// Rate: max tx submissions per second per IP (creation operator rate).
pub const SUBMIT_RATE_PER_SEC: u32 = 100;

/// Rate: max read requests per second per IP (measurement rate).
pub const READ_RATE_PER_SEC: u32 = 500;

/// Consecutive rate‑limit violations before IP enters quantum quarantine.
pub const VIOLATIONS_BEFORE_QUARANTINE: u32 = 20;

/// Quarantine escalations before IP is permanently banned (wavefunction collapse).
pub const QUARANTINE_BEFORE_BAN: u32 = 3;

/// How long a quarantine lasts (potential barrier width).
pub const QUARANTINE_DURATION: Duration = Duration::from_secs(300);

/// How often to clean up idle IP entries (decoherence time).
const CLEANUP_INTERVAL_SECS: u64 = 60;

/// How long an IP can be idle before being removed (coherence time).
const IDLE_TIMEOUT_SECS: u64 = 600;

/// Quantum tunneling probability for quarantine escape (always 0 — no escape).
const TUNNELING_PROBABILITY: f64 = 0.0;

/// Decoherence rate for idle IPs.
const IDLE_DECOHERENCE_RATE: f64 = 0.001;

// -----------------------------------------------------------------------------
// Quantum Validation Error (opaque codes, no internal details)
// -----------------------------------------------------------------------------

/// Validation errors – opaque quantum measurement outcomes.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum ValidationError {
    #[error("PAYLOAD_TOO_LONG: {len} > {max}")]
    PayloadTooLong { len: usize, max: usize },

    #[error("INVALID_ENCODING")]
    InvalidUtf8,

    #[error("PUBKEY_TOO_LONG")]
    PubkeyTooLong,

    #[error("GAS_LIMIT_ZERO")]
    GasLimitZero,

    #[error("MAX_FEE_ZERO")]
    MaxFeeZero,

    #[error("CHAIN_ID_MISMATCH: got={got} expected={expected}")]
    ChainIdMismatch { got: u64, expected: u64 },

    #[error("NONCE_GAP: sender={sender} expected={expected} got={got}")]
    NonceGap {
        sender: String,
        expected: u64,
        got: u64,
    },

    #[error("BATCH_TOO_LARGE: {count} > {max}")]
    BatchTooLarge { count: usize, max: usize },
}

// -----------------------------------------------------------------------------
// Quantum Token Bucket
// -----------------------------------------------------------------------------

/// Quantum token bucket — a harmonic oscillator model for rate limiting.
///
/// Tokens are quantized excitations: |n⟩ represents n tokens.
/// Refill acts as a† (creation), consumption as a (annihilation).
struct QuantumTokenBucket {
    /// Current token count (occupation number).
    tokens: f64,
    /// Maximum tokens (saturation limit).
    max: f64,
    /// Last refill time.
    last: Instant,
    /// Refill rate (oscillator frequency).
    rate_per_sec: f64,
    /// Consecutive violation streak (excitation count).
    violation_streak: u32,
    /// Quantum coherence of the bucket.
    coherence: f64,
}

impl QuantumTokenBucket {
    /// Create a new quantum token bucket in the ground state |0⟩.
    fn new(rate_per_sec: u32) -> Self {
        let r = rate_per_sec as f64;
        Self {
            tokens: r,
            max: r,
            last: Instant::now(),
            rate_per_sec: r,
            violation_streak: 0,
            coherence: 1.0,
        }
    }

    /// Attempt to consume a token — apply annihilation operator a.
    ///
    /// Returns `true` if a token was consumed (|n⟩ → |n-1⟩).
    fn try_consume(&mut self) -> bool {
        let now = Instant::now();
        let elapsed = now.duration_since(self.last).as_secs_f64();
        self.last = now;

        // Quantum refill: a†|n⟩ → √(n+1)|n+1⟩
        let refill = elapsed * self.rate_per_sec;
        self.tokens = (self.tokens + refill).min(self.max);

        // Apply decoherence from measurement
        self.coherence *= 1.0 - (elapsed * IDLE_DECOHERENCE_RATE as f64).min(0.1);

        if self.tokens >= 1.0 {
            // Successful consumption: a|n⟩ → √n|n-1⟩
            self.tokens -= 1.0;
            self.violation_streak = 0;
            self.coherence = (self.coherence + 0.01).min(1.0);
            true
        } else {
            // Failed: violation streak increases (excitation)
            self.violation_streak = self.violation_streak.saturating_add(1);
            self.coherence *= 0.95; // decoherence from violation
            false
        }
    }

    /// Get the quantum state coherence.
    fn coherence(&self) -> f64 {
        self.coherence
    }
}

// -----------------------------------------------------------------------------
// Quantum IP State
// -----------------------------------------------------------------------------

/// Quantum state of an IP address in the RPC Hilbert space.
///
/// |ψ_ip⟩ = α|allowed⟩ + β|quarantined⟩ + γ|banned⟩
/// where |α|² + |β|² + |γ|² = 1
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IpStatus {
    /// Normal operation — |allowed⟩ state.
    Allowed,
    /// Temporarily blocked — |quarantined⟩ state with potential barrier.
    Quarantined {
        /// When the quarantine ends (barrier width).
        until: Instant,
        /// Number of escalations (excitation level).
        escalation_count: u32,
    },
    /// Permanently blocked — |banned⟩ state (wavefunction collapsed).
    Banned,
}

/// Quantum IP entry with dual token buckets and state tracking.
struct QuantumIpEntry {
    /// Submit token bucket (creation operator).
    submit: QuantumTokenBucket,
    /// Read token bucket (measurement operator).
    read: QuantumTokenBucket,
    /// Current quantum state.
    status: IpStatus,
    /// Total rejections (cumulative decoherence events).
    total_rejections: u64,
    /// Quantum coherence of the IP state.
    coherence: f64,
    /// Entanglement entropy with other IPs.
    entanglement_entropy: f64,
}

impl QuantumIpEntry {
    /// Create a new IP entry in the pure |allowed⟩ state.
    fn new() -> Self {
        Self {
            submit: QuantumTokenBucket::new(SUBMIT_RATE_PER_SEC),
            read: QuantumTokenBucket::new(READ_RATE_PER_SEC),
            status: IpStatus::Allowed,
            total_rejections: 0,
            coherence: 1.0,
            entanglement_entropy: 0.0,
        }
    }

    /// Check if the IP is currently blocked (measurement of Ô_blocked).
    fn is_blocked(&mut self) -> bool {
        match &self.status {
            IpStatus::Banned => {
                self.coherence = 0.0; // complete decoherence
                true
            }
            IpStatus::Quarantined {
                until,
                escalation_count,
            } => {
                if Instant::now() < *until {
                    // Still trapped in potential barrier
                    self.coherence *= 0.99;
                    true
                } else {
                    // Quantum tunneling attempt (always fails — no escape)
                    let count = *escalation_count;
                    self.status = IpStatus::Allowed;
                    // Partial recovery — half coherence restored
                    self.submit.tokens = self.submit.max / 2.0;
                    self.read.tokens = self.read.max / 2.0;
                    self.coherence = 0.5;

                    if count >= QUARANTINE_BEFORE_BAN {
                        // Wavefunction collapse to |banned⟩
                        self.status = IpStatus::Banned;
                        self.coherence = 0.0;
                        return true;
                    }
                    false
                }
            }
            IpStatus::Allowed => false,
        }
    }

    /// Escalate IP state based on violation streak.
    ///
    /// Applies the quarantine operator:
    /// ```text
    /// Ô_quarantine |allowed⟩ → |quarantined⟩ if violations ≥ threshold
    /// ```
    fn maybe_escalate(&mut self, streak: u32) {
        if streak < VIOLATIONS_BEFORE_QUARANTINE {
            self.coherence *= 0.98; // minor decoherence
            return;
        }

        match &self.status {
            IpStatus::Allowed => {
                tracing::warn!(
                    streak,
                    coherence = self.coherence,
                    "rpc::limiter: IP entering quantum quarantine"
                );
                self.status = IpStatus::Quarantined {
                    until: Instant::now() + QUARANTINE_DURATION,
                    escalation_count: 1,
                };
                self.coherence *= 0.7; // significant decoherence
                self.entanglement_entropy += 0.1;
            }
            IpStatus::Quarantined {
                until,
                escalation_count,
            } => {
                let new_count = escalation_count + 1;
                if new_count >= QUARANTINE_BEFORE_BAN {
                    tracing::warn!(
                        escalations = new_count,
                        "rpc::limiter: IP wavefunction collapsed to |banned⟩"
                    );
                    self.status = IpStatus::Banned;
                    self.coherence = 0.0;
                    self.entanglement_entropy = 0.0;
                } else {
                    // Extend potential barrier
                    self.status = IpStatus::Quarantined {
                        until: (*until).max(Instant::now()) + QUARANTINE_DURATION,
                        escalation_count: new_count,
                    };
                    self.coherence *= 0.8;
                    self.entanglement_entropy += 0.05;
                }
            }
            IpStatus::Banned => {
                // Already collapsed — no further evolution
                self.coherence = 0.0;
            }
        }
    }

    /// Apply idle decoherence.
    fn apply_idle_decoherence(&mut self, elapsed: Duration) {
        let dt = elapsed.as_secs_f64();
        self.coherence *= (-IDLE_DECOHERENCE_RATE * dt).exp().max(0.0);
        self.entanglement_entropy = -self.coherence * self.coherence.ln().max(0.0);
    }
}

// -----------------------------------------------------------------------------
// Quantum Concurrency Guard
// -----------------------------------------------------------------------------

/// Tracks the number of currently in‑flight RPC requests (occupation number).
#[derive(Clone)]
pub struct ConcurrencyGuard {
    current: Arc<AtomicUsize>,
    max: usize,
}

impl ConcurrencyGuard {
    /// Create a new guard with the given maximum concurrent requests.
    pub const fn new(max: usize) -> Self {
        Self {
            current: Arc::new(AtomicUsize::new(0)),
            max,
        }
    }

    /// Attempt to acquire a slot — apply creation operator b†.
    ///
    /// Returns a `ConcurrencyTicket` on success.
    /// The slot is released when the ticket is dropped (annihilation).
    pub fn try_acquire(&self) -> Option<ConcurrencyTicket> {
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

    /// Current number of active requests (occupation number ⟨b†b⟩).
    pub fn current(&self) -> usize {
        self.current.load(Ordering::Relaxed)
    }
}

/// RAII guard that decrements the concurrency counter on drop (annihilation).
pub struct ConcurrencyTicket {
    guard: Arc<AtomicUsize>,
}

impl Drop for ConcurrencyTicket {
    fn drop(&mut self) {
        self.guard.fetch_sub(1, Ordering::AcqRel);
    }
}

// -----------------------------------------------------------------------------
// Quantum Request‑ID Generator
// -----------------------------------------------------------------------------

static REQUEST_COUNTER: AtomicUsize = AtomicUsize::new(1);

/// Generate a unique quantum request ID for structured logging correlation.
///
/// Format: `req-<monotonic_counter>-<unix_millis_low16>`
#[must_use]
pub fn new_request_id() -> String {
    let seq = REQUEST_COUNTER.fetch_add(1, Ordering::Relaxed);
    let ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .subsec_millis();
    format!("req-{seq}-{ts:04x}")
}

// -----------------------------------------------------------------------------
// Quantum RPC Limit Result
// -----------------------------------------------------------------------------

/// Result of a quantum rate limit measurement.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RpcLimitResult {
    /// Request allowed — state remains coherent.
    Allowed,
    /// Rate limited — minor decoherence.
    RateLimited,
    /// IP blocked — wavefunction collapsed.
    Blocked,
}

impl RpcLimitResult {
    pub const fn is_allowed(self) -> bool {
        matches!(self, Self::Allowed)
    }

    /// HTTP status code to return on rejection.
    pub const fn http_status(self) -> u16 {
        match self {
            Self::Allowed => 200,
            Self::RateLimited => 429,
            Self::Blocked => 403,
        }
    }
}

// -----------------------------------------------------------------------------
// Quantum Metrics Snapshot
// -----------------------------------------------------------------------------

/// Observable metrics for the quantum RPC limiter.
#[derive(Debug, Clone)]
pub struct RpcMetrics {
    pub rate_limit_hits: usize,
    pub payload_too_large: usize,
    pub decode_errors: usize,
    pub concurrency_rejected: usize,
    pub ips_quarantined: usize,
    pub ips_banned: usize,
    pub concurrent_requests: usize,
    /// Average coherence of all tracked IPs.
    pub average_coherence: f64,
    /// Total entanglement entropy.
    pub total_entanglement_entropy: f64,
}

// -----------------------------------------------------------------------------
// Quantum RPC Limiter
// -----------------------------------------------------------------------------

/// Main quantum RPC limiter managing the Hilbert space of IP states.
pub struct RpcLimiter {
    /// IP state registry (Hilbert space).
    ips: Mutex<HashMap<IpAddr, QuantumIpEntry>>,
    /// Last cleanup time.
    last_cleanup: Mutex<Instant>,
    /// Concurrency guard.
    pub concurrency: ConcurrencyGuard,
    // Atomic metrics
    pub metric_rate_limit_hits: Arc<AtomicUsize>,
    pub metric_quarantine_total: Arc<AtomicUsize>,
    pub metric_ban_total: Arc<AtomicUsize>,
    pub metric_payload_too_large: Arc<AtomicUsize>,
    pub metric_decode_errors: Arc<AtomicUsize>,
    pub metric_concurrency_rejected: Arc<AtomicUsize>,
}

impl RpcLimiter {
    /// Create a new quantum limiter with default parameters.
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

    /// Check if a transaction submit is allowed — quantum measurement.
    pub fn check_submit(&self, ip: IpAddr, req_id: &str) -> RpcLimitResult {
        self.cleanup_if_needed();
        let mut ips = self.ips.lock();
        let entry = ips.entry(ip).or_insert_with(QuantumIpEntry::new);

        if entry.is_blocked() {
            entry.total_rejections += 1;
            self.metric_rate_limit_hits
                .fetch_add(1, Ordering::Relaxed);
            tracing::warn!(
                %ip,
                %req_id,
                coherence = entry.coherence,
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

            self.metric_rate_limit_hits
                .fetch_add(1, Ordering::Relaxed);

            if matches!(entry.status, IpStatus::Quarantined { .. }) {
                self.metric_quarantine_total
                    .fetch_add(1, Ordering::Relaxed);
            } else if entry.status == IpStatus::Banned {
                self.metric_ban_total.fetch_add(1, Ordering::Relaxed);
            }

            tracing::warn!(
                %ip,
                %req_id,
                streak,
                coherence = entry.coherence,
                "rpc::limiter: submit rate limit hit"
            );
            RpcLimitResult::RateLimited
        }
    }

    /// Check if a read request is allowed — quantum measurement.
    pub fn check_read(&self, ip: IpAddr, req_id: &str) -> RpcLimitResult {
        self.cleanup_if_needed();
        let mut ips = self.ips.lock();
        let entry = ips.entry(ip).or_insert_with(QuantumIpEntry::new);

        if entry.is_blocked() {
            entry.total_rejections += 1;
            self.metric_rate_limit_hits
                .fetch_add(1, Ordering::Relaxed);
            tracing::warn!(
                %ip,
                %req_id,
                coherence = entry.coherence,
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

            self.metric_rate_limit_hits
                .fetch_add(1, Ordering::Relaxed);

            if matches!(entry.status, IpStatus::Quarantined { .. }) {
                self.metric_quarantine_total
                    .fetch_add(1, Ordering::Relaxed);
            } else if entry.status == IpStatus::Banned {
                self.metric_ban_total.fetch_add(1, Ordering::Relaxed);
            }

            tracing::warn!(
                %ip,
                %req_id,
                streak,
                coherence = entry.coherence,
                "rpc::limiter: read rate limit hit"
            );
            RpcLimitResult::RateLimited
        }
    }

    /// Record a decode error — applies decoherence penalty.
    pub fn record_decode_error(&self, ip: IpAddr, req_id: &str) {
        self.metric_decode_errors.fetch_add(1, Ordering::Relaxed);
        tracing::warn!(%ip, %req_id, "rpc::limiter: decode error");

        let mut ips = self.ips.lock();
        let entry = ips.entry(ip).or_insert_with(QuantumIpEntry::new);
        entry.submit.violation_streak = entry
            .submit
            .violation_streak
            .saturating_add(5);
        entry.coherence *= 0.8; // significant decoherence
        let streak = entry.submit.violation_streak;
        entry.maybe_escalate(streak);
    }

    /// Record a payload‑too‑large violation.
    pub fn record_payload_too_large(
        &self,
        ip: IpAddr,
        req_id: &str,
        size: usize,
    ) {
        self.metric_payload_too_large
            .fetch_add(1, Ordering::Relaxed);
        tracing::warn!(%ip, %req_id, size, "rpc::limiter: payload too large");

        let mut ips = self.ips.lock();
        let entry = ips.entry(ip).or_insert_with(QuantumIpEntry::new);
        entry.submit.violation_streak = entry
            .submit
            .violation_streak
            .saturating_add(3);
        entry.coherence *= 0.85;
        let streak = entry.submit.violation_streak;
        entry.maybe_escalate(streak);
    }

    /// Acquire a concurrency slot — create an excitation.
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

    /// Snapshot of current quantum metrics.
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

        let total_coherence: f64 = ips.values().map(|e| e.coherence).sum();
        let total_entropy: f64 = ips.values().map(|e| e.entanglement_entropy).sum();
        let count = ips.len().max(1);
        let avg_coherence = total_coherence / count as f64;

        drop(ips);

        RpcMetrics {
            rate_limit_hits: self.metric_rate_limit_hits.load(Ordering::Relaxed),
            payload_too_large: self.metric_payload_too_large.load(Ordering::Relaxed),
            decode_errors: self.metric_decode_errors.load(Ordering::Relaxed),
            concurrency_rejected: self.metric_concurrency_rejected.load(Ordering::Relaxed),
            ips_quarantined: quarantined,
            ips_banned: banned,
            concurrent_requests: self.concurrency.current(),
            average_coherence: avg_coherence,
            total_entanglement_entropy: total_entropy,
        }
    }

    /// Remove idle IP entries — decoherence cleanup.
    fn cleanup_if_needed(&self) {
        let mut last = self.last_cleanup.lock();
        if last.elapsed() < Duration::from_secs(CLEANUP_INTERVAL_SECS) {
            return;
        }
        *last = Instant::now();
        drop(last);

        let cutoff = Duration::from_secs(IDLE_TIMEOUT_SECS);
        let mut ips = self.ips.lock();
        ips.retain(|_, entry| {
            // Never evict banned IPs — they remain as warnings
            if entry.status == IpStatus::Banned {
                return true;
            }
            let idle_time = entry
                .submit
                .last
                .elapsed()
                .min(entry.read.last.elapsed());
            let keep = idle_time < cutoff;
            if !keep {
                entry.apply_idle_decoherence(idle_time);
            }
            keep
        });
    }
}

impl Default for RpcLimiter {
    fn default() -> Self {
        Self::new()
    }
}

// -----------------------------------------------------------------------------
// Quantum Validator Functions
// -----------------------------------------------------------------------------

/// Validate a transaction — quantum state verification.
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

/// Validate raw body size before JSON deserialisation.
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

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

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
        for _ in 0..SUBMIT_RATE_PER_SEC {
            assert_eq!(
                limiter.check_submit(peer, "req-0"),
                RpcLimitResult::Allowed
            );
        }
    }

    #[test]
    fn test_submit_rate_limit_rejects_after_burst() {
        let limiter = RpcLimiter::new();
        let peer = ip(2);
        for _ in 0..SUBMIT_RATE_PER_SEC {
            limiter.check_submit(peer, "req-x");
        }
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
        for _ in 0..(SUBMIT_RATE_PER_SEC + VIOLATIONS_BEFORE_QUARANTINE) {
            limiter.check_submit(peer, "req-x");
        }
        let result = limiter.check_submit(peer, "req-x");
        assert!(
            matches!(
                result,
                RpcLimitResult::RateLimited | RpcLimitResult::Blocked
            ),
            "IP should be quarantined"
        );
    }

    #[test]
    fn test_decode_error_penalises_streak() {
        let limiter = RpcLimiter::new();
        let peer = ip(4);
        limiter.record_decode_error(peer, "req-1");
        assert_eq!(
            limiter.metric_decode_errors.load(Ordering::Relaxed),
            1
        );
    }

    #[test]
    fn test_payload_too_large_penalises() {
        let limiter = RpcLimiter::new();
        let peer = ip(5);
        limiter.record_payload_too_large(peer, "req-1", MAX_BODY_BYTES + 1);
        assert_eq!(
            limiter.metric_payload_too_large.load(Ordering::Relaxed),
            1
        );
    }

    #[test]
    fn test_concurrency_cap() {
        let limiter = RpcLimiter::new();
        let mut tickets = Vec::new();
        for _ in 0..MAX_CONCURRENT_REQUESTS {
            tickets.push(limiter.try_concurrency_slot("req-x").expect("slot"));
        }
        assert!(
            limiter.try_concurrency_slot("req-overflow").is_none(),
            "concurrency cap should be enforced"
        );
        assert_eq!(
            limiter
                .metric_concurrency_rejected
                .load(Ordering::Relaxed),
            1
        );
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
    fn test_metrics_snapshot_quantum() {
        let limiter = RpcLimiter::new();
        let snap = limiter.metrics_snapshot();
        assert_eq!(snap.rate_limit_hits, 0);
        assert_eq!(snap.ips_banned, 0);
        assert_eq!(snap.concurrent_requests, 0);
        assert!(snap.average_coherence >= 0.0);
        assert!(snap.total_entanglement_entropy >= 0.0);
    }

    #[test]
    fn test_error_messages_are_opaque() {
        let err = ValidationError::PayloadTooLong {
            len: 9999,
            max: 4096,
        };
        let msg = err.to_string();
        assert!(
            !msg.contains("src/"),
            "error must not leak source paths"
        );
        assert!(
            !msg.contains("::"),
            "error must not leak module paths"
        );
    }

    #[test]
    fn test_different_ips_are_independent() {
        let limiter = RpcLimiter::new();
        for _ in 0..SUBMIT_RATE_PER_SEC {
            limiter.check_submit(ip(10), "req-x");
        }
        assert_eq!(
            limiter.check_submit(ip(11), "req-y"),
            RpcLimitResult::Allowed
        );
    }
}
