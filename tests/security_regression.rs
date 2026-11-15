//! Security regression test suite.
//!
//! Every test here reproduces a specific security bug that was found and
//! fixed. Regression tests are the audit trail for past incidents:
//! their value is entirely in the fact that they **fail on the buggy
//! code and pass on the fixed code**, so any test that would pass
//! whether the bug is present or not is worse than no test at all.
//!
//! # Policy: adding a new regression test
//!
//! 1. Reproduce the bug with a failing test first.
//! 2. Verify the test fails on `main` (pre-fix).
//! 3. Fix the bug.
//! 4. Verify the test passes on the fix.
//! 5. Merge both the fix and the test in the same PR.
//!
//! # What this file tests
//!
//! Library APIs only:
//!
//! * `iona::rpc_limits` — input validation and rate limiting.
//! * `iona::net::peer_score` — peer scoring and per-peer quotas.
//! * `iona::consensus::double_sign` — persistent double-sign guard.
//! * `iona::storage` — migration correctness.
//!
//! # What this file **cannot** test
//!
//! Anything that lives in the `iona-node` **binary** rather than a
//! library: startup permission gates, `--unsafe-rpc-public` bind
//! checks, refusal to start with a missing guard file for an existing
//! validator, and similar CLI-level behaviour. Those are tested in
//! `iona-node`'s own integration tests. Tests in this file must not
//! pretend to exercise binary-level behaviour via library APIs; such
//! tests end up tautological (`assert!(x.is_ok() || x.is_err())`) or
//! test the wrong thing.
//!
//! # Categories
//!
//! * **§1 RPC validation** — zero gas, zero fee, chain ID mismatch,
//!   stale nonce, oversized payload, oversized batch.
//! * **§2 Rate limiting** — flood escalates to quarantine; per-IP
//!   buckets are independent.
//! * **§3 P2P peer score** — message flood penalty, validation slot
//!   cap, banned-peer lockout, oversized-message penalty.
//! * **§4 Consensus double-sign guard** — double-proposal refusal,
//!   persistence across restart, chain-hash tamper detection, fresh
//!   directory creates a working guard.
//! * **§5 Networking** — peer-ID sanity in the scoring layer.
//! * **§6 Storage** — migration handles missing state file; migration
//!   preserves user-authored `node_meta.json`.
//!
//! # Running
//!
//! ```text
//! cargo test --test security_regressions
//! ```

use iona::consensus::double_sign::DoubleSignGuard;
use iona::crypto::PublicKeyBytes;
use iona::net::peer_score::{
    PeerScore, ViolationReason, BAN_THRESHOLD, PEER_MAX_PENDING_VALIDATIONS,
};
use iona::rpc_limits::{
    validate_batch_size, validate_body_size, validate_tx, RpcLimitResult, RpcLimiter,
    ValidationError, MAX_BATCH_ITEMS, MAX_BODY_BYTES, SUBMIT_RATE_PER_SEC,
    VIOLATIONS_BEFORE_QUARANTINE,
};
use iona::types::{Hash32, Tx};

use std::net::{IpAddr, Ipv4Addr};
use tempfile::TempDir;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

const VALID_CHAIN_ID: u64 = 1;

/// Distinct test IPs in the 192.168.1.0/24 range.
fn test_ip(octet: u8) -> IpAddr {
    IpAddr::V4(Ipv4Addr::new(192, 168, 1, octet))
}

fn hash(byte: u8) -> Hash32 {
    Hash32([byte; 32])
}

/// Builder for a valid baseline transaction. Every method overrides one
/// field so the failure mode of each test is unambiguous.
struct TxBuilder {
    chain_id: u64,
    nonce: u64,
    gas_limit: u64,
    max_fee: u64,
    priority_fee: u64,
    payload: String,
}

impl TxBuilder {
    fn valid() -> Self {
        Self {
            chain_id: VALID_CHAIN_ID,
            nonce: 0,
            gas_limit: 21_000,
            max_fee: 1,
            priority_fee: 1,
            payload: "ok".into(),
        }
    }
    fn chain_id(mut self, v: u64) -> Self { self.chain_id = v; self }
    fn nonce(mut self, v: u64) -> Self { self.nonce = v; self }
    fn gas_limit(mut self, v: u64) -> Self { self.gas_limit = v; self }
    fn max_fee(mut self, v: u64) -> Self { self.max_fee = v; self }
    fn priority_fee(mut self, v: u64) -> Self { self.priority_fee = v; self }
    fn payload(mut self, v: impl Into<String>) -> Self { self.payload = v.into(); self }
    fn build(self) -> Tx {
        Tx {
            pubkey: vec![0u8; 32],
            from: "alice".into(),
            nonce: self.nonce,
            max_fee_per_gas: self.max_fee,
            max_priority_fee_per_gas: self.priority_fee,
            gas_limit: self.gas_limit,
            payload: self.payload,
            signature: vec![0u8; 64],
            chain_id: self.chain_id,
        }
    }
}

/// Validate against the canonical chain ID and the given confirmed nonce.
fn check_tx(tx: &Tx, confirmed_nonce: u64) -> Result<(), ValidationError> {
    validate_tx(tx, VALID_CHAIN_ID, confirmed_nonce)
}

struct TestEnv {
    _temp: TempDir,
    path: String,
}

impl TestEnv {
    fn new() -> Self {
        let dir = TempDir::new().expect("tempdir");
        let path = dir.path().to_str().expect("utf-8 path").to_string();
        Self { _temp: dir, path }
    }
    fn path(&self) -> &str { &self.path }
}

// ===========================================================================
// §1 RPC validation
// ===========================================================================

#[test]
fn regression_rpc_zero_gas_limit_rejected() {
    let tx = TxBuilder::valid().gas_limit(0).build();
    assert!(
        matches!(check_tx(&tx, 0), Err(ValidationError::GasLimitZero)),
        "gas_limit=0 must produce GasLimitZero; got {:?}",
        check_tx(&tx, 0),
    );
}

#[test]
fn regression_rpc_zero_max_fee_rejected() {
    // Set both fee fields to 0 so this test does not depend on the
    // order in which validate_tx checks them.
    let tx = TxBuilder::valid().max_fee(0).priority_fee(0).build();
    assert!(
        matches!(check_tx(&tx, 0), Err(ValidationError::MaxFeeZero)),
        "max_fee_per_gas=0 must produce MaxFeeZero; got {:?}",
        check_tx(&tx, 0),
    );
}

#[test]
fn regression_rpc_wrong_chain_id_rejected() {
    let tx = TxBuilder::valid().chain_id(9_999).build();
    assert!(
        matches!(
            check_tx(&tx, 0),
            Err(ValidationError::ChainIdMismatch { .. }),
        ),
        "chain_id mismatch must produce ChainIdMismatch (cross-chain replay)",
    );
}

#[test]
fn regression_rpc_past_nonce_rejected() {
    // nonce 5 < confirmed 10.
    let tx = TxBuilder::valid().nonce(5).build();
    assert!(
        matches!(check_tx(&tx, 10), Err(ValidationError::NonceGap { .. })),
        "past nonce must produce NonceGap (replay protection)",
    );
}

#[test]
fn regression_rpc_oversized_payload_rejected_by_tx_validation() {
    let giant = "x".repeat(MAX_BODY_BYTES + 1);
    let tx = TxBuilder::valid().payload(giant).build();
    assert!(
        matches!(check_tx(&tx, 0), Err(ValidationError::PayloadTooLong { .. })),
        "oversized tx payload must produce PayloadTooLong",
    );
}

#[test]
fn regression_rpc_oversized_body_rejected_by_size_gate() {
    let body = vec![0u8; MAX_BODY_BYTES + 1];
    assert!(
        validate_body_size(&body, MAX_BODY_BYTES).is_err(),
        "request body over MAX_BODY_BYTES must be rejected",
    );
}

#[test]
fn regression_rpc_oversized_batch_rejected() {
    assert!(
        matches!(
            validate_batch_size(MAX_BATCH_ITEMS + 1),
            Err(ValidationError::BatchTooLarge { .. }),
        ),
        "batch over MAX_BATCH_ITEMS must produce BatchTooLarge",
    );
}

// Removed: `regression_rpc_invalid_signature_rejected`.
//
// The previous test set `signature = vec![0u8; 32]` and then asserted
// `result.is_ok() || result.is_err()` — a tautology. Signature
// verification is not `validate_tx`'s job; it happens in the
// transaction decoder before `validate_tx` runs. Testing signature
// rejection from this library-level file would require either an RPC
// handler or a decoder API that is not exposed here. Signature
// verification bugs are covered in the decoder's own tests. The
// regression test that used to live here was providing false
// confidence, not coverage.

// ===========================================================================
// §2 Rate limiting
// ===========================================================================

/// Sustained flooding must escalate from `RateLimited` to `Blocked`
/// (quarantine). `RateLimited` and `Blocked` are distinct states:
/// `RateLimited` means "try again later"; `Blocked` means the IP is
/// quarantined or banned. Asserting `RateLimited | Blocked` — as the
/// previous version of this test did — would pass even if quarantine
/// never fired.
#[test]
fn regression_rate_limit_flood_escalates_to_quarantine() {
    let limiter = RpcLimiter::new();
    let peer = test_ip(50);

    // Budget: drain the rate-limit bucket, cross the quarantine
    // threshold, plus a small buffer to observe the post-quarantine
    // state. Uses the public constants so the test tracks any change
    // to their values.
    let budget = (SUBMIT_RATE_PER_SEC as usize)
        .saturating_add(VIOLATIONS_BEFORE_QUARANTINE as usize)
        .saturating_add(5);

    let mut saw_rate_limited = false;
    let mut saw_blocked = false;
    for i in 0..budget {
        match limiter.check_submit(peer, &format!("req-{i}")) {
            RpcLimitResult::RateLimited => saw_rate_limited = true,
            RpcLimitResult::Blocked => saw_blocked = true,
            RpcLimitResult::Allowed => {
                // Only the first `SUBMIT_RATE_PER_SEC` calls should be
                // allowed; anything past that budget is a rate-limiter
                // bug that this test will catch.
                assert!(
                    i < SUBMIT_RATE_PER_SEC as usize,
                    "request {i} was Allowed past the rate-limit budget",
                );
            }
        }
    }

    assert!(saw_rate_limited, "flood must produce at least one RateLimited");
    assert!(
        saw_blocked,
        "sustained flood must escalate to Blocked (quarantine); \
         the pre-quarantine rate limit alone is not enough",
    );
    assert_eq!(
        limiter.check_submit(peer, "req-post-quarantine"),
        RpcLimitResult::Blocked,
        "quarantined IP must remain Blocked on subsequent requests",
    );

    let snap = limiter.metrics_snapshot();
    assert!(
        snap.ips_quarantined >= 1 || snap.ips_banned >= 1,
        "metrics must reflect the quarantine/ban; got {snap:?}",
    );
}

/// Per-IP buckets must be independent. A flood from one IP must not
/// consume another IP's budget — otherwise an attacker could dilute
/// their own rate limit by spoofing many source addresses.
#[test]
fn regression_rate_limit_ip_buckets_are_independent() {
    let limiter = RpcLimiter::new();
    let ip_a = test_ip(60);
    let ip_b = test_ip(61);

    for _ in 0..SUBMIT_RATE_PER_SEC {
        let _ = limiter.check_submit(ip_a, "drain");
    }
    assert_eq!(
        limiter.check_submit(ip_a, "overflow"),
        RpcLimitResult::RateLimited,
        "IP A must be rate-limited after draining its bucket",
    );

    assert_eq!(
        limiter.check_submit(ip_b, "fresh"),
        RpcLimitResult::Allowed,
        "IP B must be unaffected by IP A's flood",
    );
}

// ===========================================================================
// §3 P2P peer score
// ===========================================================================

#[test]
fn regression_p2p_msg_flood_triggers_quota_rejections() {
    use iona::net::peer_score::PEER_MAX_MSGS_PER_SEC;

    let mut score = PeerScore::with_defaults();
    let limit = PEER_MAX_MSGS_PER_SEC as usize;

    let mut rejected = 0usize;
    for _ in 0..(limit * 3) {
        if !score.check_msg_quota("peer-flood") {
            rejected += 1;
        }
    }
    assert!(
        rejected > 0,
        "message flood over 3× PEER_MAX_MSGS_PER_SEC must trigger rejections",
    );
}

#[test]
fn regression_p2p_validation_slot_cap_enforced() {
    let mut score = PeerScore::with_defaults();
    for i in 0..PEER_MAX_PENDING_VALIDATIONS {
        assert!(
            score.acquire_validation_slot("peer-attack"),
            "slot {i} of {PEER_MAX_PENDING_VALIDATIONS} must be available",
        );
    }
    assert!(
        !score.acquire_validation_slot("peer-attack"),
        "the {}+1th concurrent validation slot must be rejected",
        PEER_MAX_PENDING_VALIDATIONS,
    );
}

#[test]
fn regression_p2p_banned_peer_blocked_from_all_traffic() {
    let mut score = PeerScore::with_defaults();
    score.penalise_with(
        "peer-evil",
        ViolationReason::InvalidBlock,
        BAN_THRESHOLD.unsigned_abs() as i64 + 50,
    );
    assert!(score.should_ban("peer-evil"), "peer must be banned");
    assert!(
        !score.check_msg_quota("peer-evil"),
        "banned peer must fail the message quota check",
    );
    assert!(
        !score.check_byte_quota("peer-evil", 1),
        "banned peer must fail the byte quota check even for a 1-byte payload",
    );
}

#[test]
fn regression_p2p_oversized_message_penalised() {
    let mut score = PeerScore::with_defaults();
    let oversize = 2 * 1024 * 1024; // 2 MiB — well over any sane quota.
    assert!(
        !score.check_byte_quota("peer-flood", oversize),
        "2 MiB message must be rejected by the byte quota",
    );
    assert!(
        score.score("peer-flood") < 0,
        "rejecting an oversized message must penalise the peer below zero",
    );
}

// ===========================================================================
// §4 Consensus double-sign guard
// ===========================================================================

#[test]
fn regression_consensus_double_proposal_refused() {
    let env = TestEnv::new();
    let pk = PublicKeyBytes(vec![10u8; 32]);
    let guard = DoubleSignGuard::new(env.path(), &pk).expect("fresh guard");

    guard
        .record_proposal(1, 0, &hash(2))
        .expect("record first proposal");

    assert!(
        guard.check_proposal(1, 0, &hash(1)).is_err(),
        "double-proposal (different hash at the same position) must be refused",
    );
}

#[test]
fn regression_consensus_guard_persists_across_restart() {
    let env = TestEnv::new();
    let pk = PublicKeyBytes(vec![11u8; 32]);

    {
        let guard = DoubleSignGuard::new(env.path(), &pk).expect("first instance");
        guard.record_proposal(5, 0, &hash(5)).expect("record");
    }

    let guard = DoubleSignGuard::new(env.path(), &pk).expect("second instance");
    assert!(
        guard.check_proposal(5, 0, &hash(99)).is_err(),
        "guard after restart must refuse a conflicting proposal at the same position",
    );
    assert!(
        guard.check_proposal(5, 0, &hash(5)).is_ok(),
        "guard after restart must still accept an exact replay of the recorded proposal",
    );
}

#[test]
fn regression_consensus_tampered_guard_file_rejected() {
    use std::fs;

    let env = TestEnv::new();
    let pk = PublicKeyBytes(vec![12u8; 32]);

    // Create a valid guard, then tamper with its chain hash. Use the
    // public accessor `guard.path()` rather than hard-coding the
    // on-disk filename layout, so this test does not break if the
    // storage layout ever changes.
    let guard_file = {
        let guard = DoubleSignGuard::new(env.path(), &pk).expect("create");
        guard.record_proposal(1, 0, &hash(2)).expect("record");
        guard.path().to_owned()
    };

    let raw = fs::read_to_string(&guard_file).expect("read guard file");
    let mut json: serde_json::Value =
        serde_json::from_str(&raw).expect("parse guard file as JSON");
    json["chain_hash"] = serde_json::json!("deadbeef");
    fs::write(
        &guard_file,
        serde_json::to_string(&json).expect("serialize tampered guard"),
    )
    .expect("write tampered guard");

    let result = DoubleSignGuard::new(env.path(), &pk);
    assert!(
        result.is_err(),
        "guard file with a tampered chain hash must be rejected at load",
    );
}

/// A fresh data directory must produce a working guard, not an error.
///
/// The related policy — "an existing validator must refuse to start
/// when its guard file is missing" — is enforced in the `iona-node`
/// binary's startup code, not by `DoubleSignGuard` itself, and is not
/// testable from this library-level file. Do not attempt to test that
/// policy here via `DoubleSignGuard::new`, which has no way to
/// distinguish a fresh node from a validator whose guard file was
/// deleted.
#[test]
fn regression_consensus_fresh_directory_creates_working_guard() {
    let env = TestEnv::new();
    let pk = PublicKeyBytes(vec![13u8; 32]);

    let guard = DoubleSignGuard::new(env.path(), &pk)
        .expect("fresh directory must produce a working guard");
    let (proposals, votes) = guard.record_count();
    assert_eq!(proposals, 0, "fresh guard must have zero proposals");
    assert_eq!(votes, 0, "fresh guard must have zero votes");

    // The guard must be usable immediately.
    guard.record_proposal(1, 0, &hash(1)).expect("record");
    assert!(guard.check_proposal(1, 0, &hash(1)).is_ok());
    assert!(guard.check_proposal(1, 0, &hash(2)).is_err());
}

// ===========================================================================
// §5 Networking — peer-ID sanity in the scoring layer
// ===========================================================================

#[test]
fn regression_net_empty_peer_id_rejected_by_quota_check() {
    let mut score = PeerScore::with_defaults();
    assert!(
        !score.check_msg_quota(""),
        "empty peer ID must not pass the message quota check",
    );
}

#[test]
fn regression_net_very_long_peer_id_rejected_by_quota_check() {
    let mut score = PeerScore::with_defaults();
    let long_id = "x".repeat(1024 * 1024);
    assert!(
        !score.check_msg_quota(&long_id),
        "1 MiB peer ID must not pass the message quota check",
    );
}

// Removed: `regression_net_malformed_multiaddress_handled`.
//
// The test name promised multiaddress parsing coverage, but the test
// body only exercised `PeerScore::check_msg_quota` with a long string.
// The comment itself acknowledged "This test would require the
// multiaddress parser". It was renamed to
// `regression_net_very_long_peer_id_rejected_by_quota_check` to
// reflect what it actually tests. The multiaddress parser has its
// own regression tests in `tests/net_addrs.rs` (or wherever the
// address decoder lives), where it can be exercised directly.

// ===========================================================================
// §6 Storage — migration correctness
// ===========================================================================

#[test]
fn regression_storage_migration_handles_missing_state_file() {
    let env = TestEnv::new();
    let data = iona::storage::DataDir::new(env.path());
    data.ensure_schema_and_migrate()
        .expect("migration must succeed on a directory with no state file");
}

#[test]
fn regression_storage_migration_preserves_existing_node_meta() {
    use std::fs;

    let env = TestEnv::new();
    let custom = serde_json::json!({
        "protocol_version": 2,
        "node_id": "custom-node",
        "created_at": 1_234_567_890u64,
    });
    let meta_path = format!("{}/node_meta.json", env.path());
    fs::write(
        &meta_path,
        serde_json::to_string_pretty(&custom).expect("serialize node_meta"),
    )
    .expect("write node_meta");

    let data = iona::storage::DataDir::new(env.path());
    data.ensure_schema_and_migrate().expect("migration");

    let raw = fs::read_to_string(&meta_path).expect("read node_meta");
    let meta: serde_json::Value = serde_json::from_str(&raw).expect("parse node_meta");
    assert_eq!(
        meta["node_id"], "custom-node",
        "migration must preserve user-authored node_meta.json",
    );
}

// Removed: `regression_general_public_writable_data_dir_detected`.
//
// The public-writable-directory check lives in `iona-node`'s startup
// code, not in `iona::storage::DataDir`. The previous test called
// `DataDir::ensure_schema_and_migrate` and asserted
// `result.is_ok() || result.is_err()` — a tautology — because the
// library has no permission gate to exercise. A mirror of the check
// lives in `tests/rpc_security_gates.rs` where it can actually be
// verified; it does not belong here.

// Removed: `regression_general_request_id_unique`.
//
// This is a property of the request-ID generator, tested thoroughly
// in `tests/rpc_hardening.rs` with a 10 000-sample uniqueness check
// and a charset check. It is not a security regression — no specific
// incident prompted it.

// Removed: `regression_general_error_messages_no_paths`.
//
// Same rationale — the error-opacity properties are covered in
// `tests/rpc_hardening.rs` and `tests/rpc_security_gates.rs` with a
// fuller leak-pattern list. This file's purpose is regression
// tracking for specific past incidents, not comprehensive negative
// testing. Duplicating the checks here dilutes the signal that
// "everything in this file is a real regression test".

// Removed: `regression_suite_has_minimum_coverage`.
//
// The previous test counted `std::env::args()` values containing
// "regression" and asserted the count was at least 20. But test
// binaries don't receive test names as command-line arguments; they
// receive flags like `--test-threads`, `--nocapture`, and optionally
// a single substring filter. So the count was either 1 (the binary
// path itself, if it contained "regression") or 0 (if run without a
// filter and with a different binary name) — and
// `assert!(count >= 20)` would fail in both cases. The test was not
// only useless, it was broken.
//
// If a "do not delete regression tests" guard is desired, implement
// it as a CI check that greps the file for `#[test]` and compares
// against a minimum, not as a runtime test.
