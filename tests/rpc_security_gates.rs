//! Negative / security-gate tests for the RPC hardening layer.
//!
//! Evidence for the "hard-mode" claims in `docs/SECURITY_FIRST.md`.
//! This file is scoped to the startup and request-layer gates (G1–G7).
//! General RPC negative/adversarial tests (concurrency cap, batch
//! size, request-ID generation, error opacity) live in
//! `tests/rpc_hardening.rs`; they are not duplicated here.
//!
//! # What is verified here
//!
//! | Gate | What is tested |
//! |------|----------------|
//! | G1   | `validate_body_size` rejects oversized bodies (at-limit, one-over, far-over) and accepts empty / at-limit bodies. |
//! | G2   | Per-IP rate limiting on read and submit paths; the rate-limit metric increments when the limit trips; other IPs are unaffected. |
//! | G3   | `json_nesting_depth` handles flat, at-limit, over-limit, strings-with-braces, and escape sequences that would confuse a naïve parser. |
//! | G4   | `MAX_HEADER_BYTES` is in a sane range and typical header sets fit within it. |
//! | G5   | `is_public_bind` (mirror) classifies loopback / wildcard / external addresses correctly and fails **closed** on unrecognised forms. |
//! | G6   | Key-file permission gate (mirror) rejects modes broader than `0600` on Unix. |
//! | G7   | Data-directory permission gate (mirror) rejects modes broader than `0700` on Unix. |
//!
//! # Mirrored logic
//!
//! G5, G6, and G7 test **mirrors** of production logic that is not
//! currently exposed from `iona`. If the production logic changes, the
//! mirrors below and their tests must change together; there is no
//! automatic consistency check. A future refactor should move
//! `is_public_bind` and `check_key_permissions` into a public
//! `iona::startup` module so these tests can call the real functions
//! directly.
//!
//! # Not tested here
//!
//! * HTTP status codes (413, 429, 431) — that requires an HTTP server
//!   or a middleware round-trip. This file verifies the predicates the
//!   server uses to decide, not the wire-level response.
//! * Actual memory growth after rejecting an oversized body — not
//!   observable from a unit test. G1 verifies the rejection; memory
//!   growth is checked at the allocator level in benchmarks.
//! * Header-size **enforcement** — the validation function is not
//!   exposed. G4 only verifies the constant and the arithmetic that a
//!   future enforcement would use.
//! * Directory / file permission checks on non-Unix platforms (the
//!   Unix permission model does not apply on Windows).
//!
//! # Running
//!
//! ```text
//! cargo test --test rpc_security_gates
//! ```

use std::net::IpAddr;
use std::sync::atomic::Ordering;

use iona::rpc::middleware::{json_nesting_depth, MAX_HEADER_BYTES, MAX_JSON_DEPTH};
use iona::rpc_limits::{
    new_request_id, validate_body_size, RpcLimitResult, RpcLimiter, MAX_BODY_BYTES,
    SUBMIT_RATE_PER_SEC, VIOLATIONS_BEFORE_QUARANTINE,
};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// IPs used across tests. Each test uses its own limiter, so octets
/// only matter as identifiers in failure messages.
const HOT_IP_READ:    &str = "10.0.0.1";
const HOT_IP_SUBMIT:  &str = "10.1.1.1";
const COLD_IP:        &str = "10.0.0.2";
const QUARANTINE_IP:  &str = "10.0.0.3";

/// Upper bound on iterations for any "flood until tripped" loop.
///
/// The loop breaks on the first non-`Allowed` result, so this is only
/// the budget used when the rate limiter fails to trip — in which case
/// the test must fail fast, not spin. `SUBMIT_RATE_PER_SEC * 2 + 10`
/// is comfortably above any realistic burst threshold.
const fn flood_budget() -> usize {
    (SUBMIT_RATE_PER_SEC as usize) * 2 + 10
}

/// Test addresses for the public-bind predicate.
const LOOPBACK_IPV4:    &str = "127.0.0.1:9001";
const LOOPBACK_IPV4_2:  &str = "127.0.0.2:9001";
const LOOPBACK_IPV4_NP: &str = "127.0.0.1";         // no port
const LOOPBACK_IPV6:    &str = "[::1]:9001";
const LOOPBACK_IPV6_NP: &str = "::1";               // no brackets, no port
const LOCALHOST:        &str = "localhost:9001";
const LOCALHOST_NP:     &str = "localhost";
const LOCALHOST_UPPER:  &str = "LOCALHOST:9001";
const WILDCARD_IPV4:    &str = "0.0.0.0:9001";
const WILDCARD_IPV4_NP: &str = "0.0.0.0";
const WILDCARD_IPV6:    &str = "[::]:9001";
const EXTERNAL_IP:      &str = "192.168.1.10:9001";
const EXTERNAL_IP_NP:   &str = "192.168.1.10";
const IPV4_MAPPED_V6:   &str = "[::ffff:127.0.0.1]:9001";
const MALFORMED_V6:     &str = "[::1";              // no close bracket
const PORT_ONLY:        &str = ":9001";

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn ip(addr: &str) -> IpAddr {
    addr.parse().expect("test IP must parse")
}

fn flood_req_id(i: usize) -> String {
    // `req-` prefix matches the production format; the `flood-` infix
    // keeps test IDs distinguishable in failure messages.
    format!("req-flood-{i}")
}

// ===========================================================================
// G1 — Body size limits
// ===========================================================================

#[test]
fn g1_body_exactly_at_limit_is_accepted() {
    let body = vec![0u8; MAX_BODY_BYTES];
    assert!(
        validate_body_size(&body, MAX_BODY_BYTES).is_ok(),
        "body of exactly {MAX_BODY_BYTES} bytes must be accepted",
    );
}

#[test]
fn g1_body_one_byte_over_limit_is_rejected() {
    let body = vec![0u8; MAX_BODY_BYTES + 1];
    assert!(
        validate_body_size(&body, MAX_BODY_BYTES).is_err(),
        "body of {} bytes (limit + 1) must be rejected",
        MAX_BODY_BYTES + 1,
    );
}

/// Various overshoots, all of which must be rejected.
///
/// (The previous name promised a memory-growth check; that is not
/// observable from a unit test, and the module header now says so.)
#[test]
fn g1_various_oversized_bodies_are_rejected() {
    for extra in [1usize, 100, 1_000, 1_000_000] {
        let body = vec![0u8; MAX_BODY_BYTES + extra];
        assert!(
            validate_body_size(&body, MAX_BODY_BYTES).is_err(),
            "body {extra} bytes over limit must be rejected",
        );
    }
}

/// Documents the current empty-body policy: allowed at the size gate.
///
/// A handler may still reject an empty body when it tries to parse it
/// as JSON; that is a separate layer. If the size-gate policy changes
/// to "reject empty", this test and the policy must change together.
#[test]
fn g1_empty_body_is_accepted_by_size_gate() {
    assert!(validate_body_size(&[], MAX_BODY_BYTES).is_ok());
}

// ===========================================================================
// G2 — Rate-limit flood
// ===========================================================================

/// Flooding one IP must trip **rate limiting** (not quarantine) and
/// must not affect other IPs.
#[test]
fn g2_read_flood_rate_limits_hot_ip_but_not_cold_ip() {
    let limiter = RpcLimiter::new();
    let hot  = ip(HOT_IP_READ);
    let cold = ip(COLD_IP);

    let mut trips = 0usize;
    let mut first_limit: Option<RpcLimitResult> = None;
    for i in 0..flood_budget() {
        let r = limiter.check_read(hot, &flood_req_id(i));
        if r != RpcLimitResult::Allowed {
            first_limit = Some(r);
            trips += 1;
            break;
        }
    }
    assert_eq!(
        first_limit,
        Some(RpcLimitResult::RateLimited),
        "hot IP must be RateLimited (not quarantined) after a burst; \
         observed {first_limit:?} after {trips} attempts",
    );

    // Cold IP unaffected.
    let cold_req = new_request_id();
    assert_eq!(
        limiter.check_read(cold, &cold_req),
        RpcLimitResult::Allowed,
        "cold IP must not be affected by another IP's flood",
    );
}

/// Same as the read flood, on the submit path.
#[test]
fn g2_submit_flood_rate_limits_hot_ip() {
    let limiter = RpcLimiter::new();
    let hot = ip(HOT_IP_SUBMIT);

    let mut first_limit: Option<RpcLimitResult> = None;
    for i in 0..flood_budget() {
        let r = limiter.check_submit(hot, &flood_req_id(i));
        if r != RpcLimitResult::Allowed {
            first_limit = Some(r);
            break;
        }
    }
    assert_eq!(
        first_limit,
        Some(RpcLimitResult::RateLimited),
        "hot IP must be RateLimited after a submit flood",
    );
}

/// Each rate-limit hit must increment the metric.
#[test]
fn g2_rate_limit_hits_increment_metric() {
    let limiter = RpcLimiter::new();
    let hot = ip(HOT_IP_READ);

    // Trip the limit once.
    let mut tripped = false;
    for i in 0..flood_budget() {
        if limiter.check_read(hot, &flood_req_id(i)) != RpcLimitResult::Allowed {
            tripped = true;
            break;
        }
    }
    assert!(tripped, "flood must trip the rate limit");

    assert!(
        limiter.metric_rate_limit_hits.load(Ordering::Relaxed) >= 1,
        "metric_rate_limit_hits must be incremented after a rate-limited request",
    );
}

// ===========================================================================
// G3 — JSON nesting depth
// ===========================================================================

#[test]
fn g3_flat_json_within_limit() {
    let depth = json_nesting_depth(br#"{"key":"value","n":42}"#);
    assert!(
        depth <= MAX_JSON_DEPTH,
        "flat JSON must be within depth limit, got {depth}",
    );
}

#[test]
fn g3_nested_json_at_limit_accepted() {
    let mut s = String::new();
    for _ in 0..MAX_JSON_DEPTH { s.push('{'); }
    s.push_str(r#""k":1"#);
    for _ in 0..MAX_JSON_DEPTH { s.push('}'); }

    let depth = json_nesting_depth(s.as_bytes());
    assert_eq!(
        depth, MAX_JSON_DEPTH,
        "JSON nested exactly MAX_JSON_DEPTH deep must have depth {MAX_JSON_DEPTH}",
    );
}

#[test]
fn g3_deeply_nested_json_exceeds_limit() {
    let levels = MAX_JSON_DEPTH + 1;
    let mut s = String::new();
    for _ in 0..levels { s.push('{'); }
    s.push_str(r#""k":1"#);
    for _ in 0..levels { s.push('}'); }

    let depth = json_nesting_depth(s.as_bytes());
    assert!(
        depth > MAX_JSON_DEPTH,
        "JSON nested {} deep must exceed MAX_JSON_DEPTH={MAX_JSON_DEPTH}, got {depth}",
        levels,
    );
}

/// Braces inside JSON strings must not inflate the reported depth.
#[test]
fn g3_braces_inside_strings_not_counted() {
    // The value contains 32 `{` characters but they are string data.
    let json = br#"{"key": "{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{}}"#;
    assert_eq!(
        json_nesting_depth(json), 1,
        "braces inside a string literal must not inflate depth",
    );
}

/// An escaped quote must not terminate the string early. If it did, the
/// `}` inside the string would close the outer object and the actual
/// nested `{}` (at depth 2) would be mis-parsed.
#[test]
fn g3_escaped_quote_inside_string_handled() {
    // String value is `"}` — the `"` is an escape, the `}` is data.
    // Outer object + inner empty object = depth 2.
    let json = br#"{"a": "\"}", "b": {}}"#;
    assert_eq!(
        json_nesting_depth(json), 2,
        "escaped quote must not truncate the string or miscount depth",
    );
}

/// A `}` inside a string value must not close the outer object.
#[test]
fn g3_close_brace_inside_string_not_counted() {
    // Value is `}` — must not be seen as closing the outer object.
    let json = br#"{"a": "}"}"#;
    assert_eq!(
        json_nesting_depth(json), 1,
        "`}}` inside a string must not close the object",
    );
}

// ===========================================================================
// G4 — Header size constant
//
// The header-validation function itself is not exposed from `iona`, so
// this file can only pin the constant's range and the arithmetic that
// a future enforcement would use. If the validator is later exposed,
// these tests should be extended to call it directly.
// ===========================================================================

#[test]
fn g4_max_header_bytes_in_sane_range() {
    assert!(
        MAX_HEADER_BYTES >= 8 * 1024,
        "MAX_HEADER_BYTES={MAX_HEADER_BYTES} is too small for typical RPC clients \
         (many send 2–4 KiB of headers under load)",
    );
    assert!(
        MAX_HEADER_BYTES <= 128 * 1024,
        "MAX_HEADER_BYTES={MAX_HEADER_BYTES} allows header blocks so large that \
         a single request can consume meaningful memory",
    );
}

#[test]
fn g4_typical_headers_fit_within_limit() {
    // `name: value\r\n` — each header costs name.len() + value.len() + 4.
    let headers: &[(&str, &str)] = &[
        ("authorization", "Bearer my-secret-token"),
        ("content-type", "application/json"),
        ("x-request-id", "req-0001-abcd"),
        ("user-agent", "iona-test-client/1.0"),
    ];
    let total: usize = headers.iter().map(|(k, v)| k.len() + v.len() + 4).sum();
    assert!(
        total < MAX_HEADER_BYTES,
        "typical header set ({total} bytes) must fit within MAX_HEADER_BYTES={MAX_HEADER_BYTES}",
    );
}

#[test]
fn g4_oversized_header_would_exceed_limit() {
    const GIANT_VALUE_LEN: usize = 100 * 1024;
    let value_len = GIANT_VALUE_LEN;
    let total = "x-custom".len() + value_len + 4;
    assert!(
        total > MAX_HEADER_BYTES,
        "a {GIANT_VALUE_LEN}-byte header value must exceed MAX_HEADER_BYTES={MAX_HEADER_BYTES}",
    );
}

// ===========================================================================
// G5 — Public-bind detection (mirror)
//
// `is_public_bind` mirrors the startup gate. It fails **closed**: any
// address whose classification is ambiguous is treated as public, so
// the operator must pass `--unsafe-rpc-public` to start. A future
// refactor should expose the production function and have this file
// call it directly.
// ===========================================================================

/// Returns `true` if binding to `addr` requires `--unsafe-rpc-public`.
fn is_public_bind(addr: &str) -> bool {
    let addr = addr.trim();
    // Fail-closed: empty is not a valid address, treat as unsafe.
    if addr.is_empty() {
        return true;
    }

    // Bare IPv6 addresses (no brackets, no port).
    if addr == "::1" { return false; }
    if addr == "::"  { return true; }

    let lower = addr.to_ascii_lowercase();
    if lower == "localhost" || lower.starts_with("localhost:") {
        return false;
    }

    // Bracketed IPv6: `[host]:port` or `[host]`.
    if addr.starts_with('[') {
        return match addr.find(']') {
            Some(end) => match &addr[1..end] {
                "::1" => false,
                "::"  => true,
                // Fail-closed: any IPv6 we don't explicitly recognise
                // (e.g. `::ffff:127.0.0.1`, link-local) is treated
                // as public.
                _ => true,
            },
            // Malformed bracket: fail-closed.
            None => true,
        };
    }

    // IPv4 or hostname.
    let host = addr.split(':').next().unwrap_or(addr);
    // `:9001` → empty host → fail-closed.
    if host.is_empty() { return true; }

    if host == "127.0.0.1" || host.starts_with("127.") { return false; }
    if host == "0.0.0.0" { return true; }

    // Any other hostname or address requires the flag.
    true
}

#[test]
fn g5_loopback_addresses_are_not_public() {
    for addr in [
        LOOPBACK_IPV4, LOOPBACK_IPV4_2, LOOPBACK_IPV4_NP,
        LOOPBACK_IPV6, LOOPBACK_IPV6_NP,
        LOCALHOST, LOCALHOST_NP, LOCALHOST_UPPER,
    ] {
        assert!(
            !is_public_bind(addr),
            "{addr:?} is loopback/localhost and must NOT require --unsafe-rpc-public",
        );
    }
}

#[test]
fn g5_wildcard_addresses_are_public() {
    for addr in [WILDCARD_IPV4, WILDCARD_IPV4_NP, WILDCARD_IPV6] {
        assert!(
            is_public_bind(addr),
            "{addr:?} is a wildcard bind and must require --unsafe-rpc-public",
        );
    }
}

#[test]
fn g5_external_addresses_are_public() {
    for addr in [EXTERNAL_IP, EXTERNAL_IP_NP] {
        assert!(
            is_public_bind(addr),
            "{addr:?} is not loopback and must require --unsafe-rpc-public",
        );
    }
}

/// Fail-closed: cases the classifier cannot confidently identify as
/// loopback must be treated as public.
#[test]
fn g5_ambiguous_inputs_are_treated_as_public() {
    // IPv4-mapped IPv6 loopback — arguably loopback, but not
    // explicitly recognised; treated as public.
    assert!(is_public_bind(IPV4_MAPPED_V6));
    // Malformed bracket.
    assert!(is_public_bind(MALFORMED_V6));
    // Port-only, empty host.
    assert!(is_public_bind(PORT_ONLY));
    // Empty string.
    assert!(is_public_bind(""));
}

// ===========================================================================
// G6 / G7 — Permission gates (Unix only, mirrors)
// ===========================================================================

#[cfg(unix)]
mod unix_perm_tests {
    use super::*;
    use std::fs;
    use std::os::unix::fs::PermissionsExt;
    use tempfile::TempDir;

    const DATA_DIR_PERM:      u32 = 0o700;
    const KEY_FILE_PERM:      u32 = 0o600;
    const BAD_DATA_DIR_PERM:  u32 = 0o755;
    const BAD_DATA_DIR_PERM2: u32 = 0o770;
    const BAD_KEY_FILE_PERM:  u32 = 0o644;

    /// Mirrors `check_key_permissions` from `iona-node`. If the
    /// production check changes, this function and its tests must
    /// change together.
    ///
    /// Rules:
    /// * Data dir, if it exists, must have no group or other bits
    ///   (`mode & 0o077 == 0`).
    /// * Key file, if it exists, must have no group or other bits and
    ///   no owner-execute bit (`mode & 0o177 == 0`) — that is, exactly
    ///   `0600`.
    fn check_key_permissions(data_dir: &str, keystore_mode: &str) -> Result<(), String> {
        let dir_path = std::path::Path::new(data_dir);

        if dir_path.exists() {
            let mode = fs::metadata(dir_path)
                .map_err(|e| format!("stat {data_dir}: {e}"))?
                .permissions()
                .mode() & 0o777;
            if mode & 0o077 != 0 {
                return Err(format!(
                    "data directory '{data_dir}' has permissions {mode:03o} — expected 0700",
                ));
            }
        }

        let key_file = match keystore_mode.trim().to_lowercase().as_str() {
            "encrypted" => format!("{data_dir}/keys.enc"),
            _ => format!("{data_dir}/keys.json"),
        };

        let key_path = std::path::Path::new(&key_file);
        if key_path.exists() {
            let mode = fs::metadata(key_path)
                .map_err(|e| format!("stat {key_file}: {e}"))?
                .permissions()
                .mode() & 0o777;
            if mode & 0o177 != 0 {
                return Err(format!(
                    "key file '{key_file}' has permissions {mode:03o} — expected 0600",
                ));
            }
        }

        Ok(())
    }

    fn setup_dir(perm: u32) -> TempDir {
        let dir = TempDir::new().expect("tempdir");
        fs::set_permissions(dir.path(), fs::Permissions::from_mode(perm)).expect("chmod dir");
        dir
    }

    fn write_key(dir: &TempDir, name: &str, perm: u32) -> std::path::PathBuf {
        let p = dir.path().join(name);
        fs::write(&p, b"{}").expect("write key");
        fs::set_permissions(&p, fs::Permissions::from_mode(perm)).expect("chmod key");
        p
    }

    #[test]
    fn g6_key_file_0600_is_accepted() {
        let dir = setup_dir(DATA_DIR_PERM);
        write_key(&dir, "keys.json", KEY_FILE_PERM);
        check_key_permissions(dir.path().to_str().unwrap(), "plain")
            .expect("0600 key file must pass");
    }

    #[test]
    fn g6_key_file_0644_is_rejected() {
        let dir = setup_dir(DATA_DIR_PERM);
        write_key(&dir, "keys.json", BAD_KEY_FILE_PERM);
        let err = check_key_permissions(dir.path().to_str().unwrap(), "plain")
            .expect_err("0644 key file must be rejected");
        assert!(err.contains("0644"), "error must name the offending mode: {err}");
    }

    #[test]
    fn g6_encrypted_key_file_0600_is_accepted() {
        let dir = setup_dir(DATA_DIR_PERM);
        write_key(&dir, "keys.enc", KEY_FILE_PERM);
        check_key_permissions(dir.path().to_str().unwrap(), "encrypted")
            .expect("encrypted 0600 key must pass");
    }

    #[test]
    fn g7_data_dir_0700_is_accepted() {
        let dir = setup_dir(DATA_DIR_PERM);
        check_key_permissions(dir.path().to_str().unwrap(), "plain")
            .expect("0700 data dir must pass");
    }

    #[test]
    fn g7_data_dir_0755_is_rejected() {
        let dir = setup_dir(BAD_DATA_DIR_PERM);
        let err = check_key_permissions(dir.path().to_str().unwrap(), "plain")
            .expect_err("0755 data dir must be rejected");
        assert!(err.contains("0755"), "error must name the offending mode: {err}");
    }

    #[test]
    fn g7_data_dir_0770_is_rejected() {
        let dir = setup_dir(BAD_DATA_DIR_PERM2);
        check_key_permissions(dir.path().to_str().unwrap(), "plain")
            .expect_err("0770 data dir (group-accessible) must be rejected");
    }
}

// ===========================================================================
// Quarantine / ban escalation (supporting G2)
// ===========================================================================

/// After enough sustained violations, the IP must be **Blocked** — not
/// merely RateLimited. Those are distinct states; a test that accepts
/// either is testing nothing.
#[test]
fn quarantine_escalates_to_blocked_after_sustained_violations() {
    let limiter = RpcLimiter::new();
    let peer = ip(QUARANTINE_IP);

    // Budget: enough submissions to drain the rate-limit bucket and
    // cross the quarantine threshold, plus a buffer.
    let total = (SUBMIT_RATE_PER_SEC as usize)
        .saturating_add(VIOLATIONS_BEFORE_QUARANTINE as usize)
        .saturating_add(5);

    for i in 0..total {
        let _ = limiter.check_submit(peer, &format!("req-{i}"));
    }

    assert_eq!(
        limiter.check_submit(peer, "req-final"),
        RpcLimitResult::Blocked,
        "IP must be Blocked after {VIOLATIONS_BEFORE_QUARANTINE} sustained violations",
    );

    let snap = limiter.metrics_snapshot();
    assert!(
        snap.ips_quarantined >= 1 || snap.ips_banned >= 1,
        "metrics must reflect the quarantine/ban: {snap:?}",
    );
}

// ===========================================================================
// RpcLimitResult contract (supporting G2's RateLimited-vs-Blocked
// distinction and the HTTP status code the server maps it to)
// ===========================================================================

#[test]
fn rpc_limit_result_is_allowed_semantics() {
    assert!(RpcLimitResult::Allowed.is_allowed());
    assert!(!RpcLimitResult::RateLimited.is_allowed());
    assert!(!RpcLimitResult::Blocked.is_allowed());
}

#[test]
fn rpc_limit_result_http_status_codes() {
    assert_eq!(RpcLimitResult::Allowed.http_status(), 200);
    assert_eq!(RpcLimitResult::RateLimited.http_status(), 429);
    assert_eq!(RpcLimitResult::Blocked.http_status(), 403);
}

// ===========================================================================
// Metrics: increment on record_* (supporting "metrics checked where
// applicable" claim in the module header)
// ===========================================================================

#[test]
fn metrics_increment_on_record_events() {
    let limiter = RpcLimiter::new();
    let peer = ip(HOT_IP_READ);

    limiter.record_decode_error(peer, "req-decode");
    limiter.record_payload_too_large(peer, "req-payload", MAX_BODY_BYTES + 100);

    let snap = limiter.metrics_snapshot();
    assert_eq!(snap.decode_errors, 1);
    assert_eq!(snap.payload_too_large, 1);
}
