//! Security regression test suite.
//!
//! Every test in this file corresponds to a specific security bug that was
//! found and fixed. The test name includes a short description and the version
//! it was fixed in (when known).
//!
//! POLICY: When a security bug is discovered and fixed:
//!   1. Add a test here that reproduces the bug (pre-fix behavior).
//!   2. Verify the test FAILS on the unfixed code.
//!   3. Fix the bug.
//!   4. Verify the test PASSES on the fixed code.
//!   5. The test stays here permanently — regressions are caught automatically.
//!
//! Tests are named: `regression_<short_description>` or `regression_<ISSUE_ID>_<desc>`.

use iona::rpc_limits::{
    validate_tx, validate_body_size, validate_batch_size,
    RpcLimiter, RpcLimitResult, MAX_BODY_BYTES, SUBMIT_RATE_PER_SEC,
};
use iona::consensus::double_sign::{DoubleSignGuard, vote_guard_key};
use iona::crypto::PublicKeyBytes;
use iona::net::peer_score::{PeerScore, ViolationReason, BAN_THRESHOLD, PEER_MAX_PENDING_VALIDATIONS};
use iona::types::{Tx, Hash32};
use std::net::{IpAddr, Ipv4Addr};

fn ip(a: u8) -> IpAddr { IpAddr::V4(Ipv4Addr::new(192, 168, 1, a)) }
fn hash(b: u8) -> Hash32 { Hash32([b; 32]) }

fn tx(chain_id: u64, nonce: u64, gas: u64, fee: u64, payload: &str) -> Tx {
    Tx {
        pubkey: vec![0u8; 32],
        from: "alice".into(),
        nonce,
        max_fee_per_gas: fee,
        max_priority_fee_per_gas: 1,
        gas_limit: gas,
        payload: payload.to_string(),
        signature: vec![0u8; 64],
        chain_id,
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// RPC surface regressions
// ─────────────────────────────────────────────────────────────────────────────

/// REGRESSION: A tx with zero gas_limit could pass validation and consume
/// block space without paying any fee (infinite gas-price griefing).
/// Fixed: validate_tx now checks gas_limit > 0.
#[test]
fn regression_zero_gas_limit_rejected() {
    let result = validate_tx(&tx(1, 0, 0, 1, "ok"), 1, 0);
    assert!(result.is_err(), "zero gas_limit must be rejected");
}

/// REGRESSION: A tx with zero max_fee could pass validation and consume
/// block space for free.
/// Fixed: validate_tx now checks max_fee_per_gas > 0.
#[test]
fn regression_zero_max_fee_rejected() {
    let result = validate_tx(&tx(1, 0, 21000, 0, "ok"), 1, 0);
    assert!(result.is_err(), "zero max_fee_per_gas must be rejected");
}

/// REGRESSION: A tx with a mismatched chain_id could be replayed on another
/// network (cross-chain replay attack).
/// Fixed: validate_tx checks chain_id matches expected.
#[test]
fn regression_wrong_chain_id_rejected() {
    let result = validate_tx(&tx(9999, 0, 21000, 1, "ok"), 1, 0);
    assert!(result.is_err(), "wrong chain_id must be rejected (cross-chain replay)");
}

/// REGRESSION: A tx with a past nonce (below confirmed) could cause a
/// double-spend if the mempool accepted it.
/// Fixed: validate_tx rejects nonce < sender_nonce.
#[test]
fn regression_past_nonce_rejected() {
    // Confirmed nonce is 10, tx nonce is 5 → must reject.
    let result = validate_tx(&tx(1, 5, 21000, 1, "ok"), 1, 10);
    assert!(result.is_err(), "past nonce must be rejected (replay protection)");
}

/// REGRESSION: An oversized payload could cause unbounded memory allocation
/// during deserialization.
/// Fixed: validate_body_size and validate_tx check payload length first.
#[test]
fn regression_oversized_payload_rejected() {
    let giant = "x".repeat(MAX_BODY_BYTES + 1);
    let result = validate_tx(&tx(1, 0, 21000, 1, &giant), 1, 0);
    assert!(result.is_err(), "oversized payload must be rejected");

    let body = vec![0u8; MAX_BODY_BYTES + 1];
    assert!(validate_body_size(&body, MAX_BODY_BYTES).is_err());
}

/// REGRESSION: A batch with too many items could exhaust CPU/memory.
/// Fixed: validate_batch_size enforces MAX_BATCH_ITEMS.
#[test]
fn regression_oversized_batch_rejected() {
    assert!(validate_batch_size(1_000_000).is_err(), "huge batch must be rejected");
}

// ─────────────────────────────────────────────────────────────────────────────
// Rate limiting regressions
// ─────────────────────────────────────────────────────────────────────────────

/// REGRESSION: The rate limiter was not tracking violations, so a flooder
/// could sustain attacks indefinitely at the burst rate.
/// Fixed: violation_streak is tracked and triggers quarantine.
#[test]
fn regression_flooder_eventually_quarantined() {
    let limiter = RpcLimiter::new();
    let peer = ip(50);
    // Flood far beyond the burst + quarantine threshold.
    let total = SUBMIT_RATE_PER_SEC * 10;
    for _ in 0..total {
        limiter.check_submit(peer, "flood");
    }
    // Must eventually be rate-limited or blocked.
    let result = limiter.check_submit(peer, "final");
    assert!(
        matches!(result, RpcLimitResult::RateLimited | RpcLimitResult::Blocked),
        "sustained flooder must be quarantined, got {result:?}"
    );
}

/// REGRESSION: Two different IPs were sharing rate-limit state, allowing
/// IP spoofing to dilute the per-IP limit.
/// Fixed: each IP has its own token bucket.
#[test]
fn regression_ip_buckets_are_independent() {
    let limiter = RpcLimiter::new();
    // Exhaust ip(60)'s budget.
    for _ in 0..SUBMIT_RATE_PER_SEC {
        limiter.check_submit(ip(60), "req");
    }
    // ip(61) must be unaffected.
    assert_eq!(
        limiter.check_submit(ip(61), "req"),
        RpcLimitResult::Allowed,
        "different IPs must have independent rate buckets"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// P2P / peer score regressions
// ─────────────────────────────────────────────────────────────────────────────

/// REGRESSION: A peer could send messages infinitely fast without being penalised,
/// enabling gossip flooding.
/// Fixed: check_msg_quota() enforces PEER_MAX_MSGS_PER_SEC.
#[test]
fn regression_peer_msg_flood_penalised() {
    use iona::net::peer_score::PEER_MAX_MSGS_PER_SEC;
    let mut ps = PeerScore::with_defaults();
    // Send more than the per-second quota in one burst.
    let limit = PEER_MAX_MSGS_PER_SEC as usize;
    let mut rejected = 0usize;
    for _ in 0..(limit * 3) {
        if !ps.check_msg_quota("peer-flood") {
            rejected += 1;
        }
    }
    assert!(rejected > 0, "msg flood must trigger quota rejections");
}

/// REGRESSION: A peer with a bad score was still allowed to submit more
/// pending validations, causing CPU exhaustion via validation queue.
/// Fixed: acquire_validation_slot() checks PEER_MAX_PENDING_VALIDATIONS.
#[test]
fn regression_peer_validation_slot_cap() {
    let mut ps = PeerScore::with_defaults();
    for _ in 0..PEER_MAX_PENDING_VALIDATIONS {
        assert!(ps.acquire_validation_slot("peer-attack"));
    }
    assert!(
        !ps.acquire_validation_slot("peer-attack"),
        "peer must not exceed pending validation cap"
    );
}

/// REGRESSION: A permanently banned peer was still allowed to acquire
/// message quota tokens.
/// Fixed: check_msg_quota returns false for score <= ban_threshold.
#[test]
fn regression_banned_peer_blocked_from_all_traffic() {
    let mut ps = PeerScore::with_defaults();
    // Force ban.
    ps.penalise_with("peer-evil", ViolationReason::InvalidBlock, BAN_THRESHOLD.unsigned_abs() as i64 + 50);
    assert!(ps.should_ban("peer-evil"), "peer must be banned");
    assert!(
        !ps.check_msg_quota("peer-evil"),
        "banned peer must not pass msg quota check"
    );
    assert!(
        !ps.check_byte_quota("peer-evil", 1),
        "banned peer must not pass byte quota check"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Double-sign guard regressions
// ─────────────────────────────────────────────────────────────────────────────

/// REGRESSION: Running two validator instances with the same key could cause
/// equivocation — both sign different blocks at the same height/round.
/// Fixed: DoubleSignGuard persists records and refuses conflicting signs.
#[test]
fn regression_double_proposal_refused() {
    let dir = tempfile::tempdir().unwrap();
    let pk = PublicKeyBytes(vec![10u8; 32]);
    let g = DoubleSignGuard::new(dir.path().to_str().unwrap(), &pk).unwrap();

    g.record_proposal(1, 0, &hash(1)).unwrap();
    let result = g.check_proposal(1, 0, &hash(2)); // different block!
    assert!(result.is_err(), "double-proposal must be refused");
}

/// REGRESSION: After a crash-restart, the guard state was not reloaded,
/// allowing a double-sign on the first vote after restart.
/// Fixed: DoubleSignGuard::new() reloads from disk; check uses in-memory + disk state.
#[test]
fn regression_guard_survives_restart() {
    let dir = tempfile::tempdir().unwrap();
    let pk = PublicKeyBytes(vec![11u8; 32]);
    let path = dir.path().to_str().unwrap();

    // First "instance": record a proposal.
    {
        let g = DoubleSignGuard::new(path, &pk).unwrap();
        g.record_proposal(5, 0, &hash(5)).unwrap();
    }

    // Second "instance" (simulates restart): must refuse conflicting proposal.
    {
        let g = DoubleSignGuard::new(path, &pk).unwrap();
        let result = g.check_proposal(5, 0, &hash(99));
        assert!(result.is_err(), "guard after restart must still refuse double-proposal");
    }
}

/// REGRESSION: The guard file could be silently rolled back to a previous
/// state by an attacker with filesystem access, allowing double-sign.
/// Fixed: hash chain on every write; load verifies chain integrity.
#[test]
fn regression_rolled_back_guard_detected() {
    use std::fs;
    let dir = tempfile::tempdir().unwrap();
    let pk = PublicKeyBytes(vec![12u8; 32]);
    let path_str = dir.path().to_str().unwrap();

    // Write a guard with a proposal.
    {
        let g = DoubleSignGuard::new(path_str, &pk).unwrap();
        g.record_proposal(1, 0, &hash(1)).unwrap();
    }

    // Read and corrupt the chain_hash (simulate rollback attack).
    let guard_file = format!("{path_str}/doublesign_{}.json", hex::encode([12u8; 32]));
    let raw = fs::read_to_string(&guard_file).unwrap();
    let mut json: serde_json::Value = serde_json::from_str(&raw).unwrap();
    json["chain_hash"] = serde_json::json!("deadbeef");
    fs::write(&guard_file, serde_json::to_string(&json).unwrap()).unwrap();

    // Reload must fail.
    let result = DoubleSignGuard::new(path_str, &pk);
    assert!(result.is_err(), "corrupted/rolled-back guard must be detected at load");
}
