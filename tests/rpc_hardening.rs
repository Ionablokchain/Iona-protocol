//! RPC hardening tests — negative/adversarial suite.
//!
//! Every test here represents a specific attack or misuse scenario
//! against the RPC limiter. All must result in a rejection — never a
//! panic, never an information leak, never acceptance.
//!
//! # Categories
//!
//! * **A. Body size limits** — the request body is rejected above
//!   [`MAX_BODY_BYTES`] and accepted at or below it.
//! * **B. Transaction validation** — structurally invalid
//!   transactions (oversized fields, zero gas, zero fee, wrong chain
//!   ID, stale nonce) are rejected with the correct variant.
//! * **C. Rate limiting** — a single IP is limited to
//!   [`SUBMIT_RATE_PER_SEC`] submits per second, independently of
//!   other IPs. Exceeding the limit returns [`RpcLimitResult::RateLimited`],
//!   **not** [`RpcLimitResult::Blocked`]. Those are distinct states:
//!   `RateLimited` means "try again later"; `Blocked` means the IP has
//!   been quarantined or banned.
//! * **D. Quarantine escalation** — [`VIOLATIONS_BEFORE_QUARANTINE`]
//!   consecutive rate-limit violations promote the IP to quarantine;
//!   further requests return `Blocked`.
//! * **E. Concurrency cap** — [`MAX_CONCURRENT_REQUESTS`] slots are
//!   enforced; slots are released when the ticket is dropped.
//! * **F. Batch size limits** — [`MAX_BATCH_ITEMS`] items are
//!   accepted; one more is rejected with
//!   [`ValidationError::BatchTooLarge`].
//! * **G. Error opacity** — displayed error messages must not leak
//!   internal paths, type names, stack traces, or debug formatting.
//! * **H. Request-ID generation** — IDs are unique and contain only
//!   ASCII-printable characters, no JSON metacharacters, no control
//!   bytes, and start with `req-`.
//! * **I. Metrics** — a freshly-constructed [`RpcLimiter`] reports
//!   zero for every counter.
//!
//! # Assumptions documented by specific tests
//!
//! * [`empty_body_is_accepted`] — the current empty-body policy is
//!   "allowed". If it changes to "rejected", this test and the policy
//!   must be updated together.
//! * [`tx_with_future_nonce_is_accepted`] — a transaction with
//!   `nonce > confirmed_nonce` is accepted with no upper bound. If a
//!   drip-prevention limit is added later, this test must be updated.
//!
//! # Running
//!
//! ```text
//! cargo test --test rpc_hardening
//! ```
//!
//! Tests run in parallel by default. Each test owns its own
//! [`RpcLimiter`] instance, so there is no cross-test interference.
//!
//! # Why there is no custom test runner
//!
//! An earlier version of this file wrapped every check in a
//! `RpcHardeningTestRunner` with its own pass/fail counters and
//! timing. That duplicated what `cargo test` already provides —
//! parallel execution, per-test failure reporting, per-test timing —
//! while making failures harder to attribute ("one of 37 checks in
//! `run_all` failed" vs. "the test `quarantine_escalates_after_
//! repeated_violations` failed at line 214"). The current version is
//! a plain set of `#[test]` functions; the framework does the rest.

use std::collections::HashSet;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::atomic::Ordering;

use iona::rpc_limits::{
    new_request_id, validate_batch_size, validate_body_size, validate_tx,
    RpcLimitResult, RpcLimiter, ValidationError, MAX_BATCH_ITEMS,
    MAX_BODY_BYTES, MAX_CONCURRENT_REQUESTS, SUBMIT_RATE_PER_SEC,
    VIOLATIONS_BEFORE_QUARANTINE,
};
use iona::types::Tx;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Number of request IDs to generate in the uniqueness test.
///
/// 10 000 is high enough that a broken counter or low-resolution
/// timestamp would produce a detectable collision, but low enough
/// that the test runs in a few milliseconds. For a UUID-v4 generator,
/// the collision probability over this sample is ~2^-70.
const REQUEST_ID_SAMPLES: usize = 10_000;

/// Multiplier for the "far over limit" body test.
const BODY_OVERSIZE_FACTOR: usize = 2;

/// Size of the oversized pubkey in the pubkey-limit test. Larger than
/// any legitimate Ed25519-derived key (which is 32 bytes).
const OVERSIZED_PUBKEY_LEN: usize = 65;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// A test IP in the reserved 10.0.0.0/8 range, distinguished only by
/// the trailing octet. Different tests use different octets so that a
/// failure message can be traced back to the test that produced it.
fn test_ip(octet: u8) -> IpAddr {
    IpAddr::V4(Ipv4Addr::new(10, 0, 0, octet))
}

/// Builder for a minimal valid transaction.
///
/// `TxBuilder::valid()` produces a transaction that must pass
/// [`validate_tx`] with `(chain_id=1, confirmed_nonce=0)`. Each method
/// overrides a single field, so tests read as:
///
/// ```ignore
/// let tx = TxBuilder::valid().gas_limit(0).build();
/// ```
///
/// which is far less error-prone than a five-positional-argument
/// constructor where three of the arguments are `u64`.
struct TxBuilder {
    chain_id: u64,
    nonce: u64,
    gas_limit: u64,
    max_fee: u64,
    pubkey: Vec<u8>,
    payload: String,
}

impl TxBuilder {
    fn valid() -> Self {
        Self {
            chain_id: 1,
            nonce: 0,
            gas_limit: 21_000,
            max_fee: 1,
            pubkey: vec![0u8; 32],
            payload: "ok".into(),
        }
    }
    fn chain_id(mut self, v: u64) -> Self { self.chain_id = v; self }
    fn nonce(mut self, v: u64) -> Self { self.nonce = v; self }
    fn gas_limit(mut self, v: u64) -> Self { self.gas_limit = v; self }
    fn max_fee(mut self, v: u64) -> Self { self.max_fee = v; self }
    fn pubkey(mut self, v: Vec<u8>) -> Self { self.pubkey = v; self }
    fn payload(mut self, v: impl Into<String>) -> Self { self.payload = v.into(); self }

    fn build(self) -> Tx {
        Tx {
            pubkey: self.pubkey,
            from: "alice".into(),
            nonce: self.nonce,
            max_fee_per_gas: self.max_fee,
            max_priority_fee_per_gas: 1,
            gas_limit: self.gas_limit,
            payload: self.payload,
            signature: vec![0u8; 64],
            chain_id: self.chain_id,
        }
    }
}

// ===========================================================================
// A. Body size limits
// ===========================================================================

#[test]
fn body_one_byte_over_limit_is_rejected() {
    let body = vec![0u8; MAX_BODY_BYTES + 1];
    assert!(
        validate_body_size(&body, MAX_BODY_BYTES).is_err(),
        "body of {} bytes must be rejected (limit is {})",
        MAX_BODY_BYTES + 1,
        MAX_BODY_BYTES,
    );
}

#[test]
fn body_far_over_limit_is_rejected() {
    let body = vec![0u8; MAX_BODY_BYTES * BODY_OVERSIZE_FACTOR];
    assert!(
        validate_body_size(&body, MAX_BODY_BYTES).is_err(),
        "body of {} bytes ({}× the limit) must be rejected",
        MAX_BODY_BYTES * BODY_OVERSIZE_FACTOR,
        BODY_OVERSIZE_FACTOR,
    );
}

#[test]
fn body_exactly_at_limit_is_accepted() {
    let body = vec![0u8; MAX_BODY_BYTES];
    assert!(
        validate_body_size(&body, MAX_BODY_BYTES).is_ok(),
        "body of exactly {} bytes must be accepted",
        MAX_BODY_BYTES,
    );
}

/// Documents the current empty-body policy: empty bodies are allowed.
///
/// If the policy changes to "rejected", this test and the policy
/// decision must change together. See the module header.
#[test]
fn empty_body_is_accepted() {
    assert!(validate_body_size(&[], MAX_BODY_BYTES).is_ok());
}

// ===========================================================================
// B. Transaction validation
// ===========================================================================

#[test]
fn tx_payload_over_limit_is_rejected() {
    // The payload limit is at most MAX_BODY_BYTES; a body-sized
    // payload is guaranteed to trip it.
    let tx = TxBuilder::valid()
        .payload("x".repeat(MAX_BODY_BYTES + 1))
        .build();
    assert!(
        matches!(
            validate_tx(&tx, 1, 0),
            Err(ValidationError::PayloadTooLong { .. }),
        ),
        "oversized payload must produce PayloadTooLong",
    );
}

#[test]
fn tx_with_zero_gas_limit_is_rejected() {
    let tx = TxBuilder::valid().gas_limit(0).build();
    assert!(
        matches!(validate_tx(&tx, 1, 0), Err(ValidationError::GasLimitZero)),
        "gas_limit=0 must produce GasLimitZero",
    );
}

#[test]
fn tx_with_zero_max_fee_is_rejected() {
    let tx = TxBuilder::valid().max_fee(0).build();
    assert!(
        matches!(validate_tx(&tx, 1, 0), Err(ValidationError::MaxFeeZero)),
        "max_fee=0 must produce MaxFeeZero",
    );
}

#[test]
fn tx_with_wrong_chain_id_is_rejected() {
    let tx = TxBuilder::valid().chain_id(9998).build();
    assert!(
        matches!(
            validate_tx(&tx, 1, 0),
            Err(ValidationError::ChainIdMismatch { .. }),
        ),
        "chain_id mismatch must produce ChainIdMismatch",
    );
}

#[test]
fn tx_with_stale_nonce_is_rejected() {
    // nonce 2 < confirmed 5: this nonce has already been used.
    let tx = TxBuilder::valid().nonce(2).build();
    assert!(
        matches!(
            validate_tx(&tx, 1, 5),
            Err(ValidationError::NonceGap { .. }),
        ),
        "nonce below confirmed must produce NonceGap",
    );
}

#[test]
fn tx_with_nonce_equal_to_confirmed_is_accepted() {
    // Idempotent replay: the next valid nonce is `confirmed`.
    let tx = TxBuilder::valid().nonce(5).build();
    assert!(
        validate_tx(&tx, 1, 5).is_ok(),
        "nonce equal to confirmed must be accepted",
    );
}

/// Documents the current "no drip limit" policy: nonces arbitrarily
/// far ahead of the confirmed nonce are accepted. If a drip-prevention
/// limit is added later, this test must be updated. See the module
/// header.
#[test]
fn tx_with_future_nonce_is_accepted() {
    let tx = TxBuilder::valid().nonce(10).build();
    assert!(
        validate_tx(&tx, 1, 5).is_ok(),
        "nonce ahead of confirmed must be accepted under current policy",
    );
}

#[test]
fn tx_with_oversized_pubkey_is_rejected() {
    let tx = TxBuilder::valid()
        .pubkey(vec![0u8; OVERSIZED_PUBKEY_LEN])
        .build();
    assert!(
        matches!(validate_tx(&tx, 1, 0), Err(ValidationError::PubkeyTooLong)),
        "{} byte pubkey must produce PubkeyTooLong",
        OVERSIZED_PUBKEY_LEN,
    );
}

// ===========================================================================
// C. Rate limiting
// ===========================================================================

/// Exceeding the per-IP rate limit returns `RateLimited`, **not**
/// `Blocked`. Those are distinct states: `Blocked` means quarantine or
/// ban, which is a separate escalation path.
#[test]
fn exceeding_rate_limit_returns_rate_limited() {
    let limiter = RpcLimiter::new();
    let peer = test_ip(1);
    for _ in 0..SUBMIT_RATE_PER_SEC {
        let _ = limiter.check_submit(peer, "drain");
    }
    assert_eq!(
        limiter.check_submit(peer, "overflow"),
        RpcLimitResult::RateLimited,
        "burst over the rate limit must return RateLimited, not Blocked",
    );
}

#[test]
fn rate_limit_hit_is_counted() {
    let limiter = RpcLimiter::new();
    let peer = test_ip(2);
    for _ in 0..SUBMIT_RATE_PER_SEC {
        let _ = limiter.check_submit(peer, "drain");
    }
    let _ = limiter.check_submit(peer, "overflow");
    assert!(
        limiter.metric_rate_limit_hits.load(Ordering::Relaxed) >= 1,
        "rate limit hit must be reflected in the metric",
    );
}

/// Rate limits are per-IP: exhausting one IP's bucket must not affect
/// another IP's ability to submit.
#[test]
fn rate_limits_are_per_ip() {
    let limiter = RpcLimiter::new();
    let ip_a = test_ip(3);
    let ip_b = test_ip(4);

    // Drain IP A's bucket.
    for _ in 0..SUBMIT_RATE_PER_SEC {
        let _ = limiter.check_submit(ip_a, "drain");
    }
    assert_eq!(limiter.check_submit(ip_a, "overflow"), RpcLimitResult::RateLimited);

    // IP B should be unaffected.
    assert_eq!(
        limiter.check_submit(ip_b, "fresh"),
        RpcLimitResult::Allowed,
        "rate limits must be per-IP, not global",
    );
}

// ===========================================================================
// D. Quarantine escalation
// ===========================================================================

#[test]
fn decode_error_is_counted() {
    let limiter = RpcLimiter::new();
    let peer = test_ip(10);
    limiter.record_decode_error(peer, "req");
    assert_eq!(
        limiter.metric_decode_errors.load(Ordering::Relaxed),
        1,
        "decode error must be counted",
    );
}

#[test]
fn payload_too_large_is_counted() {
    let limiter = RpcLimiter::new();
    let peer = test_ip(11);
    limiter.record_payload_too_large(peer, "req", MAX_BODY_BYTES + 1024);
    assert_eq!(
        limiter.metric_payload_too_large.load(Ordering::Relaxed),
        1,
        "payload-too-large must be counted",
    );
}

/// Repeated violations must escalate the IP from `RateLimited` to
/// `Blocked` (quarantine). This test verifies **both** the metric and
/// the state transition; a test that only checked
/// `RateLimited | Blocked` would pass even if quarantine never fired.
#[test]
fn quarantine_escalates_after_repeated_violations() {
    let limiter = RpcLimiter::new();
    let peer = test_ip(20);

    // Drain the rate-limit bucket.
    for _ in 0..SUBMIT_RATE_PER_SEC {
        let _ = limiter.check_submit(peer, "drain");
    }

    // Run enough violations to cross the quarantine threshold, plus a
    // buffer to observe the post-quarantine state. Record the
    // transition we observe.
    let mut saw_rate_limited = false;
    let mut saw_blocked = false;
    for i in 0..(VIOLATIONS_BEFORE_QUARANTINE + 5) {
        match limiter.check_submit(peer, &format!("violation-{i}")) {
            RpcLimitResult::RateLimited => saw_rate_limited = true,
            RpcLimitResult::Blocked => saw_blocked = true,
            RpcLimitResult::Allowed => panic!(
                "violation {i} was Allowed, expected RateLimited (pre-quarantine) \
                 or Blocked (post-quarantine)",
            ),
        }
    }

    // Verify the transition happened in the expected order.
    assert!(
        saw_rate_limited,
        "expected at least one RateLimited before quarantine; \
         saw none in {} violations",
        VIOLATIONS_BEFORE_QUARANTINE + 5,
    );
    assert!(
        saw_blocked,
        "expected at least one Blocked after quarantine; \
         quarantine never fired despite {} violations \
         (VIOLATIONS_BEFORE_QUARANTINE = {})",
        VIOLATIONS_BEFORE_QUARANTINE + 5,
        VIOLATIONS_BEFORE_QUARANTINE,
    );

    // Verify the metric agrees with the observed state.
    let snap = limiter.metrics_snapshot();
    assert!(
        snap.ips_quarantined >= 1,
        "metrics report 0 quarantined IPs, but the behavior indicates \
         quarantine fired",
    );

    // Verify the state persists.
    assert_eq!(
        limiter.check_submit(peer, "post-quarantine"),
        RpcLimitResult::Blocked,
        "quarantined IP must return Blocked on subsequent requests",
    );
}

// ===========================================================================
// E. Concurrency cap
// ===========================================================================

#[test]
fn concurrency_cap_is_enforced() {
    let limiter = RpcLimiter::new();

    // Hold all slots.
    let _tickets: Vec<_> = (0..MAX_CONCURRENT_REQUESTS)
        .map(|i| {
            limiter
                .try_concurrency_slot(&format!("req-{i}"))
                .expect("slot must be available below the cap")
        })
        .collect();

    // The next request must be rejected.
    assert!(
        limiter.try_concurrency_slot("overflow").is_none(),
        "the {}+1th concurrent request must be rejected",
        MAX_CONCURRENT_REQUESTS,
    );
    assert_eq!(
        limiter.metric_concurrency_rejected.load(Ordering::Relaxed),
        1,
        "concurrency rejection must be counted",
    );
}

#[test]
fn concurrency_slots_are_released_on_drop() {
    let limiter = RpcLimiter::new();

    let tickets: Vec<_> = (0..MAX_CONCURRENT_REQUESTS)
        .map(|i| limiter.try_concurrency_slot(&format!("req-{i}")).unwrap())
        .collect();

    assert!(limiter.try_concurrency_slot("overflow").is_none());

    // Dropping the tickets must release the slots.
    drop(tickets);
    assert!(
        limiter.try_concurrency_slot("after-drop").is_some(),
        "dropping the tickets must release the slots",
    );
}

// ===========================================================================
// F. Batch size limits
// ===========================================================================

#[test]
fn batch_at_limit_is_accepted() {
    assert!(validate_batch_size(MAX_BATCH_ITEMS).is_ok());
}

#[test]
fn batch_over_limit_is_rejected() {
    assert!(matches!(
        validate_batch_size(MAX_BATCH_ITEMS + 1),
        Err(ValidationError::BatchTooLarge { .. }),
    ));
}

#[test]
fn empty_batch_is_accepted() {
    assert!(validate_batch_size(0).is_ok());
}

// ===========================================================================
// G. Error opacity
// ===========================================================================

/// Error messages reach external callers. They must not leak source
/// paths, internal module names, Rust `Debug` formatting, stack
/// traces, or control characters.
#[test]
fn error_display_does_not_leak_internals() {
    let cases: &[ValidationError] = &[
        ValidationError::PayloadTooLong { len: 9999, max: 4096 },
        ValidationError::InvalidUtf8,
        ValidationError::PubkeyTooLong,
        ValidationError::GasLimitZero,
        ValidationError::MaxFeeZero,
        ValidationError::ChainIdMismatch { got: 2, expected: 1 },
        ValidationError::NonceGap { sender: "alice".into(), expected: 5, got: 2 },
        ValidationError::BatchTooLarge { count: 11, max: 10 },
    ];

    // Substrings that indicate an information leak from internal
    // state: paths, module names, `Debug` formatting, or stack-trace
    // markers.
    const LEAK_PATTERNS: &[&str] = &[
        "src/",            // source path
        "rpc_limits",      // internal module name
        "unwrap",          // Result::unwrap
        "expect",          // Result::expect
        "panic",           // panic message
        "ValidationError", // enum name via `{:?}`
        "Err(",            // `Debug` of Result
        "Ok(",             // `Debug` of Result
        "Some(",           // `Debug` of Option
        "\\",              // Windows path separator
    ];

    for err in cases {
        let msg = err.to_string();

        assert!(!msg.is_empty(), "error display is empty for {err:?}");

        for &pat in LEAK_PATTERNS {
            assert!(
                !msg.contains(pat),
                "error {err:?} display leaks {pat:?}: {msg:?}",
            );
        }

        // No control characters (space is allowed).
        assert!(
            !msg.chars().any(|c| c.is_control() && c != ' '),
            "error {err:?} display contains control characters: {msg:?}",
        );
    }
}

// ===========================================================================
// H. Request-ID generation
// ===========================================================================

#[test]
fn request_ids_are_unique() {
    let mut seen = HashSet::with_capacity(REQUEST_ID_SAMPLES);
    for _ in 0..REQUEST_ID_SAMPLES {
        let id = new_request_id();
        assert!(
            seen.insert(id.clone()),
            "duplicate request ID after {} samples: {id:?}",
            seen.len(),
        );
    }
}

/// Request IDs end up in HTTP headers, JSON fields, and log lines. They
/// must be safe in all three contexts: no JSON metacharacters, no shell
/// metacharacters, no ANSI escapes, no control bytes.
#[test]
fn request_ids_contain_only_safe_characters() {
    for _ in 0..256 {
        let id = new_request_id();

        // Prefix.
        assert!(
            id.starts_with("req-"),
            "request ID must start with req-: {id:?}",
        );

        // Charset: only ASCII alphanumerics, dash, underscore.
        for c in id.chars() {
            assert!(
                c.is_ascii_alphanumeric() || c == '-' || c == '_',
                "request ID {id:?} contains disallowed character {c:?}",
            );
        }

        // Belt-and-suspenders: characters that break JSON, HTTP, ANSI
        // terminals, or shell quoting. The charset check above already
        // rejects all of these, but listing them explicitly makes the
        // intent of the test clear and catches future changes to the
        // charset.
        for banned in [
            '/', '\\', '"', '\'', '{', '}', '[', ']', '<', '>', '&', '?', '#',
            '\0', '\n', '\r', '\t', '\x1b',
        ] {
            assert!(
                !id.contains(banned),
                "request ID {id:?} contains banned character {banned:?}",
            );
        }
    }
}

// ===========================================================================
// I. Metrics
// ===========================================================================

#[test]
fn fresh_limiter_has_zero_metrics() {
    let limiter = RpcLimiter::new();
    let snap = limiter.metrics_snapshot();
    assert_eq!(snap.rate_limit_hits, 0);
    assert_eq!(snap.decode_errors, 0);
    assert_eq!(snap.payload_too_large, 0);
    assert_eq!(snap.concurrency_rejected, 0);
    assert_eq!(snap.ips_banned, 0);
    assert_eq!(snap.ips_quarantined, 0);
    assert_eq!(snap.concurrent_requests, 0);
}
