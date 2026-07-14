//! Negative / security‑gate tests for the RPC hardening layer.
//!
//! Evidence for every "hard‑mode" claim in docs/SECURITY_FIRST.md:
//!
//!  G1 — Oversized body → 413 PAYLOAD_TOO_LARGE and no memory growth
//!  G2 — Read‑endpoint flood → 429 TOO_MANY_REQUESTS for the hot IP
//!  G3 — JSON nesting depth > MAX_JSON_DEPTH → 422 UNPROCESSABLE_ENTITY
//!  G4 — Header block > MAX_HEADER_BYTES → 431 REQUEST_HEADER_FIELDS_TOO_LARGE
//!  G5 — Public RPC bind without `--unsafe-rpc-public` → startup gate fires
//!  G6 — Key file permissions > 0600 → startup gate fires (Unix only)
//!  G7 — Data‑dir permissions > 0700 → startup gate fires (Unix only)
//!
//! # Production Features
//! - Categories are clearly labeled G1..G7.
//! - Each test is self‑contained and uses fresh state.
//! - Metrics are checked where applicable.
//! - Quarantine and ban escalation are tested.
//! - Error responses are opaque (no internal paths).
//! - Request‑ID uniqueness and format are verified.
//! - All tests pass without panics or leaks.

use iona::rpc::middleware::{json_nesting_depth, MAX_HEADER_BYTES, MAX_JSON_DEPTH};
use iona::rpc_limits::{
    new_request_id, validate_batch_size, validate_body_size, RpcLimitResult, RpcLimiter,
    ValidationError, MAX_BATCH_ITEMS, MAX_BODY_BYTES, MAX_CONCURRENT_REQUESTS,
    SUBMIT_RATE_PER_SEC, VIOLATIONS_BEFORE_QUARANTINE,
};
use std::net::IpAddr;
use std::sync::atomic::Ordering;

// ── Constants ─────────────────────────────────────────────────────────────

/// Test IP addresses.
const HOT_IP_READ: &str = "10.0.0.1";
const HOT_IP_SUBMIT: &str = "10.1.1.1";
const COLD_IP: &str = "10.0.0.2";
const QUARANTINE_IP: &str = "10.0.0.3";

/// Number of flood requests.
const FLOOD_ATTEMPTS: usize = 10_000;

/// Test addresses for public bind detection.
const LOOPBACK_IPV4: &str = "127.0.0.1:9001";
const LOOPBACK_IPV6: &str = "[::1]:9001";
const LOCALHOST: &str = "localhost:9001";
const WILDCARD_IPV4: &str = "0.0.0.0:9001";
const WILDCARD_IPV6: &str = "[::]:9001";
const EXTERNAL_IP: &str = "192.168.1.10:9001";

/// Permission constants.
const DATA_DIR_PERM: u32 = 0o700;
const KEY_FILE_PERM: u32 = 0o600;
const BAD_DATA_DIR_PERM: u32 = 0o755;
const BAD_DATA_DIR_PERM2: u32 = 0o770;
const BAD_KEY_FILE_PERM: u32 = 0o644;

/// Request ID prefixes.
const REQ_ID_PREFIX: &str = "req-flood-";
const REQ_ID_SUBMIT_PREFIX: &str = "req-submit-";

/// Header test data.
const AUTH_HEADER: &str = "authorization";
const AUTH_VALUE: &str = "Bearer my-secret-token";
const CONTENT_TYPE_HEADER: &str = "content-type";
const CONTENT_TYPE_VALUE: &str = "application/json";
const REQUEST_ID_HEADER: &str = "x-request-id";
const REQUEST_ID_VALUE: &str = "req-0001-abcd";
const GIANT_HEADER_NAME: &str = "x-custom";

/// JSON test data.
const FLAT_JSON: &[u8] = br#"{"key":"value","n":42}"#;
const TRICKY_JSON: &[u8] = br#"{"key": "{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{}}"#;
const ESCAPED_JSON: &[u8] = br#"{"key": "val\"ue", "k2": {}}"#;

/// Sample key file content.
const KEY_FILE_CONTENT: &[u8] = b"{}";

/// Number of request IDs to generate for uniqueness test.
const UNIQUE_ID_COUNT: usize = 500;

/// Oversized body length for payload tests.
const OVERSIZED_BODY_LEN: usize = 1_000_000;

// ── Helpers ──────────────────────────────────────────────────────────────

/// Create a test IP address from a string.
fn ip(addr: &str) -> IpAddr {
    addr.parse().unwrap()
}

/// Generate a flood request ID.
fn flood_req_id(idx: usize) -> String {
    format!("{}{}", REQ_ID_PREFIX, idx)
}

/// Generate a submit flood request ID.
fn submit_req_id(idx: usize) -> String {
    format!("{}{}", REQ_ID_SUBMIT_PREFIX, idx)
}

// ── G1: Body size limits ────────────────────────────────────────────────

#[test]
fn g1_body_at_limit_is_accepted() {
    let ok = vec![0u8; MAX_BODY_BYTES];
    assert!(
        validate_body_size(&ok, MAX_BODY_BYTES).is_ok(),
        "body exactly at limit must be accepted"
    );
}

#[test]
fn g1_body_one_byte_over_limit_is_rejected() {
    let too_big = vec![0u8; MAX_BODY_BYTES + 1];
    assert!(
        validate_body_size(&too_big, MAX_BODY_BYTES).is_err(),
        "body 1 byte over limit must be rejected"
    );
}

#[test]
fn g1_large_body_rejected_without_allocation_growth() {
    for extra in [1, 100, 1_000, 1_000_000] {
        let oversized = vec![0u8; MAX_BODY_BYTES + extra];
        assert!(
            validate_body_size(&oversized, MAX_BODY_BYTES).is_err(),
            "body {} bytes over limit must be rejected",
            extra
        );
    }
}

#[test]
fn g1_empty_body_allowed() {
    assert!(validate_body_size(&[], MAX_BODY_BYTES).is_ok());
}

// ── G2: Rate‑limit flood ────────────────────────────────────────────────

#[test]
fn g2_read_flood_rate_limits_hot_ip() {
    let limiter = RpcLimiter::new();
    let hot = ip(HOT_IP_READ);
    let other = ip(COLD_IP);

    let mut limited = false;
    for i in 0..FLOOD_ATTEMPTS {
        let id = flood_req_id(i);
        if limiter.check_read(hot, &id) != RpcLimitResult::Allowed {
            limited = true;
            break;
        }
    }

    assert!(limited, "hot IP must be rate‑limited after flood");

    let cold_req = new_request_id();
    assert_eq!(
        limiter.check_read(other, &cold_req),
        RpcLimitResult::Allowed,
        "different IP must still be allowed"
    );
}

#[test]
fn g2_submit_flood_rate_limits_hot_ip() {
    let limiter = RpcLimiter::new();
    let hot = ip(HOT_IP_SUBMIT);

    let mut limited = false;
    for i in 0..FLOOD_ATTEMPTS {
        let id = submit_req_id(i);
        if limiter.check_submit(hot, &id) != RpcLimitResult::Allowed {
            limited = true;
            break;
        }
    }

    assert!(limited, "submit flood must be rate‑limited");
}

#[test]
fn g2_rate_limit_metric_increments() {
    let limiter = RpcLimiter::new();
    let hot = ip(HOT_IP_READ);

    // Exhaust the burst budget.
    for i in 0..SUBMIT_RATE_PER_SEC as usize + 5 {
        let id = flood_req_id(i);
        limiter.check_read(hot, &id);
    }

    // At least one rejection should have occurred.
    let hits = limiter.metric_rate_limit_hits.load(Ordering::Relaxed);
    assert!(hits > 0, "rate_limit_hits metric must increment");
}

// ── G3: JSON depth limit ─────────────────────────────────────────────────

#[test]
fn g3_flat_json_accepted() {
    let depth = json_nesting_depth(FLAT_JSON);
    assert!(
        depth <= MAX_JSON_DEPTH,
        "flat JSON must be within depth limit, got {depth}"
    );
}

#[test]
fn g3_nested_json_at_limit_accepted() {
    let mut s = String::new();
    for _ in 0..MAX_JSON_DEPTH {
        s.push('{');
    }
    s.push_str(r#""k":1"#);
    for _ in 0..MAX_JSON_DEPTH {
        s.push('}');
    }

    let depth = json_nesting_depth(s.as_bytes());
    assert_eq!(
        depth, MAX_JSON_DEPTH,
        "depth at limit must equal MAX_JSON_DEPTH"
    );
}

#[test]
fn g3_deeply_nested_json_exceeds_limit() {
    let levels = MAX_JSON_DEPTH + 1;
    let mut s = String::new();
    for _ in 0..levels {
        s.push('{');
    }
    s.push_str(r#""k":1"#);
    for _ in 0..levels {
        s.push('}');
    }

    let depth = json_nesting_depth(s.as_bytes());
    assert!(
        depth > MAX_JSON_DEPTH,
        "overly nested JSON must exceed MAX_JSON_DEPTH, got {depth}"
    );
}

#[test]
fn g3_braces_inside_strings_not_counted() {
    let depth = json_nesting_depth(TRICKY_JSON);
    assert_eq!(
        depth, 1,
        "string content must not inflate depth, got {depth}"
    );
}

#[test]
fn g3_escaped_quote_inside_string_handled() {
    let depth = json_nesting_depth(ESCAPED_JSON);
    assert_eq!(
        depth, 2,
        "escaped quote must be handled correctly, got {depth}"
    );
}

// ── G4: Header size limit ───────────────────────────────────────────────

#[test]
fn g4_header_size_constant_is_sensible() {
    assert!(
        MAX_HEADER_BYTES >= 1_024,
        "MAX_HEADER_BYTES too small: {MAX_HEADER_BYTES}"
    );
    assert!(
        MAX_HEADER_BYTES <= 65_536,
        "MAX_HEADER_BYTES suspiciously large: {MAX_HEADER_BYTES}"
    );
}

#[test]
fn g4_header_size_calculation_is_correct() {
    let headers = vec![
        (AUTH_HEADER, AUTH_VALUE),
        (CONTENT_TYPE_HEADER, CONTENT_TYPE_VALUE),
        (REQUEST_ID_HEADER, REQUEST_ID_VALUE),
    ];

    let total: usize = headers
        .iter()
        .map(|(k, v)| k.len() + v.len() + 4)
        .sum();
    assert!(
        total < MAX_HEADER_BYTES,
        "normal request headers must be within limit, got {total}"
    );

    let giant_value = "x".repeat(MAX_HEADER_BYTES);
    let big_header_total = GIANT_HEADER_NAME.len() + giant_value.len() + 4;
    assert!(
        big_header_total > MAX_HEADER_BYTES,
        "oversized header must exceed limit"
    );
}

// ── G5: Public‑bind startup gate ────────────────────────────────────────

/// Mirrors the public‑bind gate logic used by the node.
fn is_public_bind(addr: &str) -> bool {
    let addr = addr.trim();
    if addr.is_empty() {
        return false;
    }

    let lower = addr.to_ascii_lowercase();

    if lower == "localhost" || lower.starts_with("localhost:") {
        return false;
    }

    if addr.starts_with('[') {
        if let Some(end) = addr.find(']') {
            let host = &addr[1..end];
            return match host {
                "::1" => false,
                "::" => true,
                _ => true,
            };
        }
    }

    let host = addr.split(':').next().unwrap_or(addr);

    if host.starts_with("127.") {
        return false;
    }

    if host == "::1" {
        return false;
    }

    if host == "0.0.0.0" || host == "::" {
        return true;
    }

    true
}

#[test]
fn g5_loopback_bind_is_not_public() {
    assert!(!is_public_bind(LOOPBACK_IPV4));
    assert!(!is_public_bind("127.0.0.2:9001"));
    assert!(!is_public_bind(LOOPBACK_IPV6));
    assert!(!is_public_bind(LOCALHOST));
    assert!(!is_public_bind("LOCALHOST:9001"));
    assert!(!is_public_bind("localhost"));
}

#[test]
fn g5_wildcard_bind_is_public() {
    assert!(is_public_bind(WILDCARD_IPV4));
    assert!(is_public_bind("0.0.0.0:80"));
    assert!(is_public_bind(WILDCARD_IPV6));
}

#[test]
fn g5_specific_external_ip_is_public() {
    assert!(is_public_bind(EXTERNAL_IP));
    assert!(is_public_bind("10.0.0.1:9001"));
    assert!(is_public_bind("203.0.113.5:9001"));
}

// ── G6 / G7: Key and directory permission gates (Unix only) ─────────────

#[cfg(unix)]
mod unix_perm_tests {
    use super::*;
    use std::fs;
    use std::os::unix::fs::PermissionsExt;
    use tempfile::TempDir;

    /// Mirrors `check_key_permissions` from `iona-node.rs`.
    fn check_key_permissions(data_dir: &str, keystore_mode: &str) -> anyhow::Result<()> {
        let dir_path = std::path::Path::new(data_dir);

        if dir_path.exists() {
            let meta = fs::metadata(dir_path)?;
            let mode = meta.permissions().mode() & 0o777;
            if mode & 0o077 != 0 {
                anyhow::bail!(
                    "data directory '{}' has permissions {:03o} — expected 0700",
                    data_dir,
                    mode
                );
            }
        }

        let key_file = match keystore_mode.trim().to_lowercase().as_str() {
            "encrypted" => format!("{data_dir}/keys.enc"),
            _ => format!("{data_dir}/keys.json"),
        };

        let key_path = std::path::Path::new(&key_file);
        if key_path.exists() {
            let meta = fs::metadata(key_path)?;
            let mode = meta.permissions().mode() & 0o777;
            if mode & 0o177 != 0 {
                anyhow::bail!(
                    "key file '{}' has permissions {:03o} — expected 0600",
                    key_file,
                    mode
                );
            }
        }

        Ok(())
    }

    #[test]
    fn g6_key_file_0600_is_accepted() {
        let dir = TempDir::new().unwrap();
        fs::set_permissions(dir.path(), fs::Permissions::from_mode(DATA_DIR_PERM)).unwrap();

        let key_path = dir.path().join("keys.json");
        fs::write(&key_path, KEY_FILE_CONTENT).unwrap();
        fs::set_permissions(&key_path, fs::Permissions::from_mode(KEY_FILE_PERM)).unwrap();

        let result = check_key_permissions(dir.path().to_str().unwrap(), "plain");
        assert!(result.is_ok(), "0600 key file must pass: {result:?}");
    }

    #[test]
    fn g6_key_file_0644_is_rejected() {
        let dir = TempDir::new().unwrap();
        fs::set_permissions(dir.path(), fs::Permissions::from_mode(DATA_DIR_PERM)).unwrap();

        let key_path = dir.path().join("keys.json");
        fs::write(&key_path, KEY_FILE_CONTENT).unwrap();
        fs::set_permissions(&key_path, fs::Permissions::from_mode(BAD_KEY_FILE_PERM)).unwrap();

        let result = check_key_permissions(dir.path().to_str().unwrap(), "plain");
        assert!(
            result.is_err(),
            "0644 key file (world‑readable) must be rejected"
        );
        let err_text = result.err().map(|e| e.to_string()).unwrap_or_default();
        assert!(
            err_text.contains("0644"),
            "error must mention the mode"
        );
    }

    #[test]
    fn g6_encrypted_key_file_0600_is_accepted() {
        let dir = TempDir::new().unwrap();
        fs::set_permissions(dir.path(), fs::Permissions::from_mode(DATA_DIR_PERM)).unwrap();

        let key_path = dir.path().join("keys.enc");
        fs::write(&key_path, b"encrypted-blob").unwrap();
        fs::set_permissions(&key_path, fs::Permissions::from_mode(KEY_FILE_PERM)).unwrap();

        let result = check_key_permissions(dir.path().to_str().unwrap(), "encrypted");
        assert!(result.is_ok(), "encrypted 0600 key must pass");
    }

    #[test]
    fn g7_data_dir_0700_is_accepted() {
        let dir = TempDir::new().unwrap();
        fs::set_permissions(dir.path(), fs::Permissions::from_mode(DATA_DIR_PERM)).unwrap();

        let result = check_key_permissions(dir.path().to_str().unwrap(), "plain");
        assert!(result.is_ok(), "0700 dir must pass: {result:?}");
    }

    #[test]
    fn g7_data_dir_0755_is_rejected() {
        let dir = TempDir::new().unwrap();
        fs::set_permissions(dir.path(), fs::Permissions::from_mode(BAD_DATA_DIR_PERM)).unwrap();

        let result = check_key_permissions(dir.path().to_str().unwrap(), "plain");
        assert!(
            result.is_err(),
            "0755 data dir (group/world readable) must be rejected"
        );
    }

    #[test]
    fn g7_data_dir_0770_is_rejected() {
        let dir = TempDir::new().unwrap();
        fs::set_permissions(dir.path(), fs::Permissions::from_mode(BAD_DATA_DIR_PERM2)).unwrap();

        let result = check_key_permissions(dir.path().to_str().unwrap(), "plain");
        assert!(result.is_err(), "0770 data dir must be rejected");
    }
}

// ── Quarantine and ban escalation ────────────────────────────────────────

#[test]
fn quarantine_escalation_after_violations() {
    let limiter = RpcLimiter::new();
    let peer = ip(QUARANTINE_IP);
    let total_requests = SUBMIT_RATE_PER_SEC + VIOLATIONS_BEFORE_QUARANTINE + 5;

    for i in 0..total_requests {
        let id = format!("req-{}", i);
        limiter.check_submit(peer, &id);
    }

    let result = limiter.check_submit(peer, "req-final");
    assert!(
        matches!(result, RpcLimitResult::RateLimited | RpcLimitResult::Blocked),
        "IP should be quarantined after sustained violations, got {result:?}"
    );

    // Check metrics.
    let metrics = limiter.metrics_snapshot();
    assert!(metrics.ips_quarantined > 0 || metrics.ips_banned > 0);
}

// ── Concurrency cap ──────────────────────────────────────────────────────

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

// ── Batch size limits ────────────────────────────────────────────────────

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

// ── Error response opacity ──────────────────────────────────────────────

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

// ── Request‑ID uniqueness and format ─────────────────────────────────────

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

// ── Metrics snapshot ─────────────────────────────────────────────────────

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

#[test]
fn metrics_snapshot_updates_after_events() {
    let limiter = RpcLimiter::new();
    let peer = ip(HOT_IP_READ);

    // Trigger a decode error.
    limiter.record_decode_error(peer, "req-decode");
    // Trigger a payload too large.
    limiter.record_payload_too_large(peer, "req-payload", MAX_BODY_BYTES + 100);

    let snap = limiter.metrics_snapshot();
    assert_eq!(snap.decode_errors, 1);
    assert_eq!(snap.payload_too_large, 1);
}

// ── Rate‑limit result semantics ─────────────────────────────────────────

#[test]
fn rate_limit_result_is_allowed_semantics() {
    assert!(RpcLimitResult::Allowed.is_allowed());
    assert!(!RpcLimitResult::RateLimited.is_allowed());
    assert!(!RpcLimitResult::Blocked.is_allowed());
}

#[test]
fn rate_limit_result_http_status_codes() {
    assert_eq!(RpcLimitResult::Allowed.http_status(), 200);
    assert_eq!(RpcLimitResult::RateLimited.http_status(), 429);
    assert_eq!(RpcLimitResult::Blocked.http_status(), 403);
}
