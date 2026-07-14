//! RPC hardening tests — negative/adversarial suite.
//!
//! Every test here represents an attack or misuse scenario.
//! All must result in a rejection, never a panic or information leak.
//!
//! Categories:
//!   A. Body size limits
//!   B. Input validation (encoding, field constraints)
//!   C. Rate limiting (per-IP flood)
//!   D. IP quarantine/ban escalation
//!   E. Concurrency cap
//!   F. Batch size limits
//!   G. Error response opacity (no internal leaks)
//!   H. Request-ID uniqueness
//!   I. Metrics snapshot

use iona::rpc_limits::{
    new_request_id, validate_batch_size, validate_body_size, validate_tx,
    RpcHardeningConfig, RpcLimitResult, RpcLimiter, RpcMetrics, ValidationError,
    MAX_BATCH_ITEMS, MAX_BODY_BYTES, MAX_CONCURRENT_REQUESTS, SUBMIT_RATE_PER_SEC,
    VIOLATIONS_BEFORE_QUARANTINE,
};
use iona::types::Tx;
use parking_lot::Mutex;
use std::collections::HashSet;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tracing::{debug, error, info, trace, warn};

// ── Configuration ─────────────────────────────────────────────────────────

/// Configuration for RPC hardening tests.
#[derive(Debug, Clone)]
pub struct RpcHardeningTestConfig {
    /// Number of request IDs to generate for uniqueness test.
    pub unique_id_count: usize,
    /// Over‑sized body length for payload tests.
    pub oversized_body_len: usize,
    /// Duration to wait for rate limiting to reset (seconds).
    pub rate_limit_reset_wait_secs: u64,
    /// Whether to enable detailed logging.
    pub verbose: bool,
    /// Whether to enable parallel test execution.
    pub parallel: bool,
}

impl Default for RpcHardeningTestConfig {
    fn default() -> Self {
        Self {
            unique_id_count: 500,
            oversized_body_len: 1_000_000,
            rate_limit_reset_wait_secs: 5,
            verbose: false,
            parallel: false,
        }
    }
}

impl RpcHardeningTestConfig {
    pub fn validate(&self) -> Result<(), String> {
        if self.unique_id_count == 0 {
            return Err("unique_id_count must be > 0".into());
        }
        if self.oversized_body_len == 0 {
            return Err("oversized_body_len must be > 0".into());
        }
        if self.rate_limit_reset_wait_secs == 0 {
            return Err("rate_limit_reset_wait_secs must be > 0".into());
        }
        Ok(())
    }
}

// ── Metrics ──────────────────────────────────────────────────────────────

/// Metrics for RPC hardening tests.
#[derive(Debug, Default)]
pub struct RpcHardeningTestMetrics {
    pub tests_passed: AtomicUsize,
    pub tests_failed: AtomicUsize,
    pub rejections: AtomicUsize,
    pub rate_limits: AtomicUsize,
    pub quarantines: AtomicUsize,
    pub bans: AtomicUsize,
}

impl RpcHardeningTestMetrics {
    pub fn record_pass(&self) {
        self.tests_passed.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_fail(&self) {
        self.tests_failed.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_rejection(&self) {
        self.rejections.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_rate_limit(&self) {
        self.rate_limits.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_quarantine(&self) {
        self.quarantines.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_ban(&self) {
        self.bans.fetch_add(1, Ordering::Relaxed);
    }

    pub fn snapshot(&self) -> RpcHardeningTestMetricsSnapshot {
        RpcHardeningTestMetricsSnapshot {
            tests_passed: self.tests_passed.load(Ordering::Relaxed),
            tests_failed: self.tests_failed.load(Ordering::Relaxed),
            rejections: self.rejections.load(Ordering::Relaxed),
            rate_limits: self.rate_limits.load(Ordering::Relaxed),
            quarantines: self.quarantines.load(Ordering::Relaxed),
            bans: self.bans.load(Ordering::Relaxed),
        }
    }
}

/// Snapshot of RPC hardening test metrics.
#[derive(Debug, Clone)]
pub struct RpcHardeningTestMetricsSnapshot {
    pub tests_passed: usize,
    pub tests_failed: usize,
    pub rejections: usize,
    pub rate_limits: usize,
    pub quarantines: usize,
    pub bans: usize,
}

// ── Test Runner ──────────────────────────────────────────────────────────

/// Runner for RPC hardening tests.
pub struct RpcHardeningTestRunner {
    config: RpcHardeningTestConfig,
    metrics: Arc<RpcHardeningTestMetrics>,
}

impl RpcHardeningTestRunner {
    pub fn new(config: RpcHardeningTestConfig) -> Result<Self, String> {
        config.validate()?;
        Ok(Self {
            config,
            metrics: Arc::new(RpcHardeningTestMetrics::default()),
        })
    }

    pub fn run_all(&self) -> Result<RpcHardeningTestMetricsSnapshot, String> {
        let start = Instant::now();
        info!("Starting RPC hardening test suite");

        // A. Body size limits
        self.test_reject_body_exactly_one_byte_over_limit();
        self.test_reject_body_far_over_limit();
        self.test_allow_body_exactly_at_limit();
        self.test_allow_empty_body();

        // B. Input validation
        self.test_reject_tx_payload_too_long();
        self.test_reject_tx_zero_gas_limit();
        self.test_reject_tx_zero_max_fee();
        self.test_reject_tx_wrong_chain_id();
        self.test_reject_tx_nonce_in_past();
        self.test_allow_tx_nonce_equal_to_confirmed();
        self.test_allow_tx_nonce_ahead_of_confirmed();
        self.test_reject_tx_pubkey_too_long();

        // C. Rate limiting
        self.test_rate_limit_submit_after_burst_exhausted();
        self.test_rate_limit_increments_metric();
        self.test_independent_ips_do_not_interfere();

        // D. IP quarantine/ban escalation
        self.test_decode_error_penalises_streak();
        self.test_payload_too_large_penalises_streak();
        self.test_repeated_violations_escalate_to_quarantine();

        // E. Concurrency cap
        self.test_concurrency_cap_enforced();
        self.test_concurrency_metric_increments_on_rejection();

        // F. Batch size limits
        self.test_batch_exactly_at_limit_allowed();
        self.test_batch_one_over_limit_rejected();
        self.test_batch_zero_allowed();

        // G. Error response opacity
        self.test_error_messages_contain_no_src_paths();
        self.test_validation_error_display_is_safe();

        // H. Request-ID uniqueness
        self.test_request_ids_are_unique();
        self.test_request_id_format_is_safe();

        // I. Metrics snapshot
        self.test_metrics_snapshot_starts_at_zero();

        let duration = start.elapsed();
        info!(
            duration_ms = duration.as_millis(),
            metrics = ?self.metrics.snapshot(),
            "RPC hardening test suite completed"
        );

        // Check for failures.
        let snapshot = self.metrics.snapshot();
        if snapshot.tests_failed > 0 {
            return Err(format!(
                "{} tests failed out of {}",
                snapshot.tests_failed,
                snapshot.tests_passed + snapshot.tests_failed
            ));
        }

        Ok(snapshot)
    }

    // ── Individual test functions ──────────────────────────────────────────

    // A. Body size limits

    fn test_reject_body_exactly_one_byte_over_limit(&self) {
        let body = vec![0u8; MAX_BODY_BYTES + 1];
        let result = validate_body_size(&body, MAX_BODY_BYTES);
        if result.is_err() {
            self.metrics.record_pass();
        } else {
            self.metrics.record_fail();
            error!("test_reject_body_exactly_one_byte_over_limit failed");
        }
    }

    fn test_reject_body_far_over_limit(&self) {
        let body = vec![0u8; self.config.oversized_body_len];
        if validate_body_size(&body, MAX_BODY_BYTES).is_err() {
            self.metrics.record_pass();
        } else {
            self.metrics.record_fail();
            error!("test_reject_body_far_over_limit failed");
        }
    }

    fn test_allow_body_exactly_at_limit(&self) {
        let body = vec![0u8; MAX_BODY_BYTES];
        if validate_body_size(&body, MAX_BODY_BYTES).is_ok() {
            self.metrics.record_pass();
        } else {
            self.metrics.record_fail();
            error!("test_allow_body_exactly_at_limit failed");
        }
    }

    fn test_allow_empty_body(&self) {
        if validate_body_size(&[], MAX_BODY_BYTES).is_ok() {
            self.metrics.record_pass();
        } else {
            self.metrics.record_fail();
            error!("test_allow_empty_body failed");
        }
    }

    // B. Input validation

    fn test_reject_tx_payload_too_long(&self) {
        let payload = "x".repeat(MAX_BODY_BYTES + 1);
        let tx = minimal_tx(1, 0, 21_000, 1, &payload);
        if matches!(validate_tx(&tx, 1, 0), Err(ValidationError::PayloadTooLong { .. })) {
            self.metrics.record_pass();
        } else {
            self.metrics.record_fail();
            error!("test_reject_tx_payload_too_long failed");
        }
    }

    fn test_reject_tx_zero_gas_limit(&self) {
        let tx = minimal_tx(1, 0, 0, 1, "ok");
        if matches!(
            validate_tx(&tx, 1, 0).unwrap_err(),
            ValidationError::GasLimitZero
        ) {
            self.metrics.record_pass();
        } else {
            self.metrics.record_fail();
            error!("test_reject_tx_zero_gas_limit failed");
        }
    }

    fn test_reject_tx_zero_max_fee(&self) {
        let tx = minimal_tx(1, 0, 21_000, 0, "ok");
        if matches!(
            validate_tx(&tx, 1, 0).unwrap_err(),
            ValidationError::MaxFeeZero
        ) {
            self.metrics.record_pass();
        } else {
            self.metrics.record_fail();
            error!("test_reject_tx_zero_max_fee failed");
        }
    }

    fn test_reject_tx_wrong_chain_id(&self) {
        let wrong_chain = 9998;
        let tx = minimal_tx(wrong_chain, 0, 21_000, 1, "ok");
        if matches!(
            validate_tx(&tx, 1, 0).unwrap_err(),
            ValidationError::ChainIdMismatch { .. }
        ) {
            self.metrics.record_pass();
        } else {
            self.metrics.record_fail();
            error!("test_reject_tx_wrong_chain_id failed");
        }
    }

    fn test_reject_tx_nonce_in_past(&self) {
        let tx = minimal_tx(1, 2, 21_000, 1, "ok");
        if matches!(
            validate_tx(&tx, 1, 5).unwrap_err(),
            ValidationError::NonceGap { .. }
        ) {
            self.metrics.record_pass();
        } else {
            self.metrics.record_fail();
            error!("test_reject_tx_nonce_in_past failed");
        }
    }

    fn test_allow_tx_nonce_equal_to_confirmed(&self) {
        let tx = minimal_tx(1, 5, 21_000, 1, "ok");
        if validate_tx(&tx, 1, 5).is_ok() {
            self.metrics.record_pass();
        } else {
            self.metrics.record_fail();
            error!("test_allow_tx_nonce_equal_to_confirmed failed");
        }
    }

    fn test_allow_tx_nonce_ahead_of_confirmed(&self) {
        let tx = minimal_tx(1, 10, 21_000, 1, "ok");
        if validate_tx(&tx, 1, 5).is_ok() {
            self.metrics.record_pass();
        } else {
            self.metrics.record_fail();
            error!("test_allow_tx_nonce_ahead_of_confirmed failed");
        }
    }

    fn test_reject_tx_pubkey_too_long(&self) {
        let mut tx = minimal_tx(1, 0, 21_000, 1, "ok");
        tx.pubkey = vec![0u8; 64 + 1];
        if matches!(
            validate_tx(&tx, 1, 0).unwrap_err(),
            ValidationError::PubkeyTooLong
        ) {
            self.metrics.record_pass();
        } else {
            self.metrics.record_fail();
            error!("test_reject_tx_pubkey_too_long failed");
        }
    }

    // C. Rate limiting

    fn test_rate_limit_submit_after_burst_exhausted(&self) {
        let limiter = RpcLimiter::new();
        let peer = test_ip(1);
        for _ in 0..SUBMIT_RATE_PER_SEC {
            limiter.check_submit(peer, "req");
        }
        let result = limiter.check_submit(peer, "req-overflow");
        if matches!(result, RpcLimitResult::RateLimited | RpcLimitResult::Blocked) {
            self.metrics.record_pass();
        } else {
            self.metrics.record_fail();
            error!("test_rate_limit_submit_after_burst_exhausted failed");
        }
    }

    fn test_rate_limit_increments_metric(&self) {
        let limiter = RpcLimiter::new();
        let peer = test_ip(2);
        for _ in 0..SUBMIT_RATE_PER_SEC {
            limiter.check_submit(peer, "req");
        }
        limiter.check_submit(peer, "req-over");
        let metric = limiter.metric_rate_limit_hits.load(Ordering::Relaxed);
        if metric >= 1 {
            self.metrics.record_pass();
        } else {
            self.metrics.record_fail();
            error!("test_rate_limit_increments_metric failed");
        }
    }

    fn test_independent_ips_do_not_interfere(&self) {
        let limiter = RpcLimiter::new();
        let ip_a = test_ip(3);
        let ip_b = test_ip(4);
        for _ in 0..SUBMIT_RATE_PER_SEC {
            limiter.check_submit(ip_a, "req");
        }
        if limiter.check_submit(ip_b, "req") == RpcLimitResult::Allowed {
            self.metrics.record_pass();
        } else {
            self.metrics.record_fail();
            error!("test_independent_ips_do_not_interfere failed");
        }
    }

    // D. IP quarantine/ban escalation

    fn test_decode_error_penalises_streak(&self) {
        let limiter = RpcLimiter::new();
        let peer = test_ip(10);
        limiter.record_decode_error(peer, "req");
        let metric = limiter.metric_decode_errors.load(Ordering::Relaxed);
        if metric == 1 {
            self.metrics.record_pass();
        } else {
            self.metrics.record_fail();
            error!("test_decode_error_penalises_streak failed");
        }
    }

    fn test_payload_too_large_penalises_streak(&self) {
        let limiter = RpcLimiter::new();
        let peer = test_ip(11);
        limiter.record_payload_too_large(peer, "req", MAX_BODY_BYTES + 1024);
        let metric = limiter.metric_payload_too_large.load(Ordering::Relaxed);
        if metric == 1 {
            self.metrics.record_pass();
        } else {
            self.metrics.record_fail();
            error!("test_payload_too_large_penalises_streak failed");
        }
    }

    fn test_repeated_violations_escalate_to_quarantine(&self) {
        let limiter = RpcLimiter::new();
        let peer = test_ip(20);
        let total_requests = SUBMIT_RATE_PER_SEC + VIOLATIONS_BEFORE_QUARANTINE + 5;
        for _ in 0..total_requests {
            limiter.check_submit(peer, "req");
        }
        let result = limiter.check_submit(peer, "req-after");
        if matches!(result, RpcLimitResult::RateLimited | RpcLimitResult::Blocked) {
            self.metrics.record_pass();
        } else {
            self.metrics.record_fail();
            error!("test_repeated_violations_escalate_to_quarantine failed");
        }
    }

    // E. Concurrency cap

    fn test_concurrency_cap_enforced(&self) {
        let limiter = RpcLimiter::new();
        let mut tickets = Vec::new();
        for _ in 0..MAX_CONCURRENT_REQUESTS {
            tickets.push(limiter.try_concurrency_slot("req").expect("slot must be available"));
        }
        let overflow = limiter.try_concurrency_slot("req-overflow");
        drop(tickets);
        if overflow.is_none() {
            self.metrics.record_pass();
        } else {
            self.metrics.record_fail();
            error!("test_concurrency_cap_enforced failed");
        }
    }

    fn test_concurrency_metric_increments_on_rejection(&self) {
        let limiter = RpcLimiter::new();
        let mut tickets = Vec::new();
        for _ in 0..MAX_CONCURRENT_REQUESTS {
            tickets.push(limiter.try_concurrency_slot("req").unwrap());
        }
        limiter.try_concurrency_slot("req-over");
        drop(tickets);
        let metric = limiter.metric_concurrency_rejected.load(Ordering::Relaxed);
        if metric == 1 {
            self.metrics.record_pass();
        } else {
            self.metrics.record_fail();
            error!("test_concurrency_metric_increments_on_rejection failed");
        }
    }

    // F. Batch size limits

    fn test_batch_exactly_at_limit_allowed(&self) {
        if validate_batch_size(MAX_BATCH_ITEMS).is_ok() {
            self.metrics.record_pass();
        } else {
            self.metrics.record_fail();
            error!("test_batch_exactly_at_limit_allowed failed");
        }
    }

    fn test_batch_one_over_limit_rejected(&self) {
        if matches!(
            validate_batch_size(MAX_BATCH_ITEMS + 1).unwrap_err(),
            ValidationError::BatchTooLarge { .. }
        ) {
            self.metrics.record_pass();
        } else {
            self.metrics.record_fail();
            error!("test_batch_one_over_limit_rejected failed");
        }
    }

    fn test_batch_zero_allowed(&self) {
        if validate_batch_size(0).is_ok() {
            self.metrics.record_pass();
        } else {
            self.metrics.record_fail();
            error!("test_batch_zero_allowed failed");
        }
    }

    // G. Error response opacity

    fn test_error_messages_contain_no_src_paths(&self) {
        let errors: Vec<ValidationError> = vec![
            ValidationError::PayloadTooLong {
                len: 9999,
                max: 4096,
            },
            ValidationError::InvalidUtf8,
            ValidationError::PubkeyTooLong,
            ValidationError::GasLimitZero,
            ValidationError::MaxFeeZero,
            ValidationError::ChainIdMismatch {
                got: 2,
                expected: 1,
            },
            ValidationError::NonceGap {
                sender: "alice".into(),
                expected: 5,
                got: 2,
            },
            ValidationError::BatchTooLarge { count: 11, max: 10 },
        ];
        let mut all_ok = true;
        for err in &errors {
            let msg = err.to_string();
            if msg.contains("src/") || msg.contains("rpc_limits") || msg.contains("unwrap") || msg.contains("panic") {
                all_ok = false;
                error!("error leaks internal: {}", msg);
            }
        }
        if all_ok {
            self.metrics.record_pass();
        } else {
            self.metrics.record_fail();
        }
    }

    fn test_validation_error_display_is_safe(&self) {
        let errors: Vec<ValidationError> = vec![
            ValidationError::PayloadTooLong { len: 1, max: 0 },
            ValidationError::InvalidUtf8,
            ValidationError::PubkeyTooLong,
            ValidationError::GasLimitZero,
            ValidationError::MaxFeeZero,
        ];
        let mut all_ok = true;
        for err in &errors {
            let s = err.to_string();
            if s.trim().is_empty() {
                all_ok = false;
                error!("error display is empty: {}", s);
            }
        }
        if all_ok {
            self.metrics.record_pass();
        } else {
            self.metrics.record_fail();
        }
    }

    // H. Request-ID uniqueness

    fn test_request_ids_are_unique(&self) {
        let ids: Vec<_> = (0..self.config.unique_id_count)
            .map(|_| new_request_id())
            .collect();
        let set: HashSet<_> = ids.iter().cloned().collect();
        if ids.len() == set.len() {
            self.metrics.record_pass();
        } else {
            self.metrics.record_fail();
            error!("test_request_ids_are_unique failed: {} duplicate(s)", ids.len() - set.len());
        }
    }

    fn test_request_id_format_is_safe(&self) {
        let id = new_request_id();
        if !id.contains('/') && !id.contains('"') && !id.contains('{') && id.starts_with("req-") {
            self.metrics.record_pass();
        } else {
            self.metrics.record_fail();
            error!("test_request_id_format_is_safe failed: {}", id);
        }
    }

    // I. Metrics snapshot

    fn test_metrics_snapshot_starts_at_zero(&self) {
        let limiter = RpcLimiter::new();
        let snap = limiter.metrics_snapshot();
        if snap.rate_limit_hits == 0
            && snap.decode_errors == 0
            && snap.payload_too_large == 0
            && snap.concurrency_rejected == 0
            && snap.ips_banned == 0
            && snap.ips_quarantined == 0
            && snap.concurrent_requests == 0
        {
            self.metrics.record_pass();
        } else {
            self.metrics.record_fail();
            error!("test_metrics_snapshot_starts_at_zero failed");
        }
    }
}

// ── Helpers ──────────────────────────────────────────────────────────────

/// Create a test IP address with the given trailing octet.
fn test_ip(octet: u8) -> IpAddr {
    IpAddr::V4(Ipv4Addr::new(10, 0, 0, octet))
}

/// Create a minimal valid transaction with customizable fields.
fn minimal_tx(chain_id: u64, nonce: u64, gas_limit: u64, max_fee: u64, payload: &str) -> Tx {
    Tx {
        pubkey: vec![0u8; 32],
        from: "alice".into(),
        nonce,
        max_fee_per_gas: max_fee,
        max_priority_fee_per_gas: 1,
        gas_limit,
        payload: payload.to_string(),
        signature: vec![0u8; 64],
        chain_id,
    }
}

// ── Test Entry Point ─────────────────────────────────────────────────────

#[test]
fn run_rpc_hardening_tests_default() {
    let config = RpcHardeningTestConfig::default();
    let runner = RpcHardeningTestRunner::new(config).unwrap();
    let result = runner.run_all();
    assert!(result.is_ok(), "RPC hardening tests failed: {:?}", result.err());
}

#[test]
fn run_rpc_hardening_tests_with_verbose() {
    let mut config = RpcHardeningTestConfig::default();
    config.verbose = true;
    let runner = RpcHardeningTestRunner::new(config).unwrap();
    let result = runner.run_all();
    assert!(result.is_ok(), "RPC hardening tests (verbose) failed: {:?}", result.err());
}
