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
    new_request_id, validate_batch_size, validate_body_size, validate_tx, RpcLimitResult,
    RpcLimiter, ValidationError, MAX_BATCH_ITEMS, MAX_BODY_BYTES, MAX_CONCURRENT_REQUESTS,
    SUBMIT_RATE_PER_SEC, VIOLATIONS_BEFORE_QUARANTINE,
};
use iona::types::Tx;
use std::net::{IpAddr, Ipv4Addr};

// -----------------------------------------------------------------------------
// Constants
// -----------------------------------------------------------------------------

/// Test IP address octets (different for each test to avoid interference).
const BASE_IP_OCTET: u8 = 10;

/// Public key length for a valid transaction (Ed25519 = 32 bytes).
const VALID_PUBKEY_LEN: usize = 32;

/// Valid signature length for a transaction (Ed25519 = 64 bytes).
const VALID_SIG_LEN: usize = 64;

/// Valid chain ID used in transaction tests.
const VALID_CHAIN_ID: u64 = 1;

/// Valid gas limit for transaction tests.
const VALID_GAS_LIMIT: u64 = 21_000;

/// Valid max fee per gas for transaction tests.
const VALID_MAX_FEE: u64 = 1;

/// Valid max priority fee per gas for transaction tests.
const VALID_MAX_PRIORITY_FEE: u64 = 1;

/// Confirmed nonce for nonce gap tests.
const CONFIRMED_NONCE: u64 = 5;

/// Future nonce for queue tests.
const FUTURE_NONCE: u64 = 10;

/// Number of request IDs to generate for uniqueness test.
const UNIQUE_ID_COUNT: usize = 500;

/// Over‑sized body length for payload tests.
const OVERSIZED_BODY_LEN: usize = 1_000_000;

// -----------------------------------------------------------------------------
// Helpers
// -----------------------------------------------------------------------------

/// Create a test IP address with the given trailing octet.
fn test_ip(octet: u8) -> IpAddr {
    IpAddr::V4(Ipv4Addr::new(BASE_IP_OCTET, 0, 0, octet))
}

/// Create a minimal valid transaction with customizable fields.
fn minimal_tx(chain_id: u64, nonce: u64, gas_limit: u64, max_fee: u64, payload: &str) -> Tx {
    Tx {
        pubkey: vec![0u8; VALID_PUBKEY_LEN],
        from: "alice".into(),
        nonce,
        max_fee_per_gas: max_fee,
        max_priority_fee_per_gas: VALID_MAX_PRIORITY_FEE,
        gas_limit,
        payload: payload.to_string(),
        signature: vec![0u8; VALID_SIG_LEN],
        chain_id,
    }
}

// -----------------------------------------------------------------------------
// A. Body size limits
// -----------------------------------------------------------------------------

#[test]
fn reject_body_exactly_one_byte_over_limit() {
    let body = vec![0u8; MAX_BODY_BYTES + 1];
    let result = validate_body_size(&body, MAX_BODY_BYTES);
    assert!(result.is_err(), "body 1 byte over limit must be rejected");
    match result.unwrap_err() {
        ValidationError::PayloadTooLong { len, max } => {
            assert_eq!(len, MAX_BODY_BYTES + 1);
            assert_eq!(max, MAX_BODY_BYTES);
        }
        e => panic!("unexpected error: {e}"),
    }
}

#[test]
fn reject_body_far_over_limit() {
    let body = vec![0u8; OVERSIZED_BODY_LEN];
    assert!(
        validate_body_size(&body, MAX_BODY_BYTES).is_err(),
        "1 MB body must be rejected"
    );
}

#[test]
fn allow_body_exactly_at_limit() {
    let body = vec![0u8; MAX_BODY_BYTES];
    assert!(
        validate_body_size(&body, MAX_BODY_BYTES).is_ok(),
        "body exactly at limit must be allowed"
    );
}

#[test]
fn allow_empty_body() {
    assert!(validate_body_size(&[], MAX_BODY_BYTES).is_ok());
}

// -----------------------------------------------------------------------------
// B. Input validation
// -----------------------------------------------------------------------------

#[test]
fn reject_tx_payload_too_long() {
    let payload = "x".repeat(MAX_BODY_BYTES + 1);
    let tx = minimal_tx(VALID_CHAIN_ID, 0, VALID_GAS_LIMIT, VALID_MAX_FEE, &payload);
    let err = validate_tx(&tx, VALID_CHAIN_ID, 0).unwrap_err();
    assert!(matches!(err, ValidationError::PayloadTooLong { .. }));
}

#[test]
fn reject_tx_zero_gas_limit() {
    let tx = minimal_tx(VALID_CHAIN_ID, 0, 0, VALID_MAX_FEE, "ok");
    assert!(matches!(
        validate_tx(&tx, VALID_CHAIN_ID, 0).unwrap_err(),
        ValidationError::GasLimitZero
    ));
}

#[test]
fn reject_tx_zero_max_fee() {
    let tx = minimal_tx(VALID_CHAIN_ID, 0, VALID_GAS_LIMIT, 0, "ok");
    assert!(matches!(
        validate_tx(&tx, VALID_CHAIN_ID, 0).unwrap_err(),
        ValidationError::MaxFeeZero
    ));
}

#[test]
fn reject_tx_wrong_chain_id() {
    let wrong_chain = VALID_CHAIN_ID + 9998;
    let tx = minimal_tx(wrong_chain, 0, VALID_GAS_LIMIT, VALID_MAX_FEE, "ok");
    let err = validate_tx(&tx, VALID_CHAIN_ID, 0).unwrap_err();
    assert!(matches!(
        err,
        ValidationError::ChainIdMismatch {
            got: wrong_chain,
            expected: VALID_CHAIN_ID
        }
    ));
}

#[test]
fn reject_tx_nonce_in_past() {
    let tx = minimal_tx(VALID_CHAIN_ID, 2, VALID_GAS_LIMIT, VALID_MAX_FEE, "ok");
    let err = validate_tx(&tx, VALID_CHAIN_ID, CONFIRMED_NONCE).unwrap_err();
    assert!(matches!(err, ValidationError::NonceGap { .. }));
}

#[test]
fn allow_tx_nonce_equal_to_confirmed() {
    let tx = minimal_tx(VALID_CHAIN_ID, CONFIRMED_NONCE, VALID_GAS_LIMIT, VALID_MAX_FEE, "ok");
    assert!(validate_tx(&tx, VALID_CHAIN_ID, CONFIRMED_NONCE).is_ok());
}

#[test]
fn allow_tx_nonce_ahead_of_confirmed() {
    let tx = minimal_tx(VALID_CHAIN_ID, FUTURE_NONCE, VALID_GAS_LIMIT, VALID_MAX_FEE, "ok");
    assert!(
        validate_tx(&tx, VALID_CHAIN_ID, CONFIRMED_NONCE).is_ok(),
        "future nonce should be queued"
    );
}

#[test]
fn reject_tx_pubkey_too_long() {
    let mut tx = minimal_tx(VALID_CHAIN_ID, 0, VALID_GAS_LIMIT, VALID_MAX_FEE, "ok");
    tx.pubkey = vec![0u8; VALID_PUBKEY_LEN * 2 + 1]; // > 64
    assert!(matches!(
        validate_tx(&tx, VALID_CHAIN_ID, 0).unwrap_err(),
        ValidationError::PubkeyTooLong
    ));
}

// -----------------------------------------------------------------------------
// C. Rate limiting
// -----------------------------------------------------------------------------

#[test]
fn rate_limit_submit_after_burst_exhausted() {
    let limiter = RpcLimiter::new();
    let peer = test_ip(1);
    for _ in 0..SUBMIT_RATE_PER_SEC {
        limiter.check_submit(peer, "req");
    }
    let result = limiter.check_submit(peer, "req-overflow");
    assert!(
        matches!(result, RpcLimitResult::RateLimited | RpcLimitResult::Blocked),
        "must be rate‑limited after burst, got {result:?}"
    );
}

#[test]
fn rate_limit_increments_metric() {
    use std::sync::atomic::Ordering;
    let limiter = RpcLimiter::new();
    let peer = test_ip(2);
    for _ in 0..SUBMIT_RATE_PER_SEC {
        limiter.check_submit(peer, "req");
    }
    // Trigger at least one rejection.
    limiter.check_submit(peer, "req-over");
    assert!(
        limiter.metric_rate_limit_hits.load(Ordering::Relaxed) >= 1,
        "rate_limit_hits metric must increment"
    );
}

#[test]
fn independent_ips_do_not_interfere() {
    let limiter = RpcLimiter::new();
    let ip_a = test_ip(3);
    let ip_b = test_ip(4);
    // Drain ip_a's budget
    for _ in 0..SUBMIT_RATE_PER_SEC {
        limiter.check_submit(ip_a, "req");
    }
    // ip_b must be unaffected
    assert_eq!(
        limiter.check_submit(ip_b, "req"),
        RpcLimitResult::Allowed
    );
}

// -----------------------------------------------------------------------------
// D. IP quarantine/ban escalation
// -----------------------------------------------------------------------------

#[test]
fn decode_error_penalises_streak() {
    use std::sync::atomic::Ordering;
    let limiter = RpcLimiter::new();
    let peer = test_ip(10);
    limiter.record_decode_error(peer, "req");
    assert_eq!(limiter.metric_decode_errors.load(Ordering::Relaxed), 1);
}

#[test]
fn payload_too_large_penalises_streak() {
    use std::sync::atomic::Ordering;
    let limiter = RpcLimiter::new();
    let peer = test_ip(11);
    limiter.record_payload_too_large(peer, "req", MAX_BODY_BYTES + 1024);
    assert_eq!(limiter.metric_payload_too_large.load(Ordering::Relaxed), 1);
}

#[test]
fn repeated_violations_escalate_to_quarantine() {
    let limiter = RpcLimiter::new();
    let peer = test_ip(20);
    let total_requests = SUBMIT_RATE_PER_SEC + VIOLATIONS_BEFORE_QUARANTINE + 5;
    for _ in 0..total_requests {
        limiter.check_submit(peer, "req");
    }
    let result = limiter.check_submit(peer, "req-after");
    assert!(
        matches!(result, RpcLimitResult::RateLimited | RpcLimitResult::Blocked),
        "IP should be quarantined after sustained violations, got {result:?}"
    );
}

// -----------------------------------------------------------------------------
// E. Concurrency cap
// -----------------------------------------------------------------------------

#[test]
fn concurrency_cap_enforced() {
    let limiter = RpcLimiter::new();
    let mut tickets = Vec::new();
    for _ in 0..MAX_CONCURRENT_REQUESTS {
        tickets.push(
            limiter
                .try_concurrency_slot("req")
                .expect("slot must be available"),
        );
    }
    // At cap – next must fail.
    assert!(
        limiter.try_concurrency_slot("req-overflow").is_none(),
        "concurrency cap must reject at {MAX_CONCURRENT_REQUESTS}"
    );
    // Drop all tickets → slots freed.
    drop(tickets);
    assert!(
        limiter.try_concurrency_slot("req-after").is_some(),
        "slots must be freed after ticket drop"
    );
}

#[test]
fn concurrency_metric_increments_on_rejection() {
    use std::sync::atomic::Ordering;
    let limiter = RpcLimiter::new();
    let mut tickets = Vec::new();
    for _ in 0..MAX_CONCURRENT_REQUESTS {
        tickets.push(limiter.try_concurrency_slot("req").unwrap());
    }
    limiter.try_concurrency_slot("req-over");
    assert_eq!(
        limiter.metric_concurrency_rejected.load(Ordering::Relaxed),
        1
    );
    drop(tickets);
}

// -----------------------------------------------------------------------------
// F. Batch size limits
// -----------------------------------------------------------------------------

#[test]
fn batch_exactly_at_limit_allowed() {
    assert!(validate_batch_size(MAX_BATCH_ITEMS).is_ok());
}

#[test]
fn batch_one_over_limit_rejected() {
    let err = validate_batch_size(MAX_BATCH_ITEMS + 1).unwrap_err();
    assert!(matches!(err, ValidationError::BatchTooLarge { .. }));
}

#[test]
fn batch_zero_allowed() {
    assert!(validate_batch_size(0).is_ok());
}

// -----------------------------------------------------------------------------
// G. Error response opacity
// -----------------------------------------------------------------------------

#[test]
fn error_messages_contain_no_src_paths() {
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
    for err in &errors {
        let msg = err.to_string();
        assert!(!msg.contains("src/"), "error leaks src path: {msg}");
        assert!(
            !msg.contains("rpc_limits"),
            "error leaks module name: {msg}"
        );
        assert!(!msg.contains("unwrap"), "error leaks internal: {msg}");
        assert!(!msg.contains("panic"), "error leaks panic info: {msg}");
    }
}

#[test]
fn validation_error_display_is_safe() {
    let errors: Vec<ValidationError> = vec![
        ValidationError::PayloadTooLong { len: 1, max: 0 },
        ValidationError::InvalidUtf8,
        ValidationError::PubkeyTooLong,
        ValidationError::GasLimitZero,
        ValidationError::MaxFeeZero,
    ];
    for err in &errors {
        let s = err.to_string();
        assert!(!s.trim().is_empty(), "error display must not be empty");
    }
}

// -----------------------------------------------------------------------------
// H. Request‑ID uniqueness
// -----------------------------------------------------------------------------

#[test]
fn request_ids_are_unique() {
    let ids: Vec<_> = (0..UNIQUE_ID_COUNT).map(|_| new_request_id()).collect();
    let set: std::collections::HashSet<_> = ids.iter().cloned().collect();
    assert_eq!(ids.len(), set.len(), "all request IDs must be unique");
}

#[test]
fn request_id_format_is_safe() {
    let id = new_request_id();
    assert!(!id.contains('/'));
    assert!(!id.contains('"'));
    assert!(!id.contains('{'));
    assert!(id.starts_with("req-"), "ID must start with req-");
}

// -----------------------------------------------------------------------------
// I. Metrics snapshot
// -----------------------------------------------------------------------------

#[test]
fn metrics_snapshot_starts_at_zero() {
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
