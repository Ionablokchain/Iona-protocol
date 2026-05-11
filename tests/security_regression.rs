//! Security regression test suite.
//!
//! Every test in this file corresponds to a specific security bug that was
//! found and fixed. The test name includes a short description and the version
//! it was fixed in (when known).
//!
//! POLICY: When a security bug is discovered and fixed:
//!   1. Add a test here that reproduces the bug (pre‑fix behaviour).
//!   2. Verify the test FAILS on the unfixed code.
//!   3. Fix the bug.
//!   4. Verify the test PASSES on the fixed code.
//!   5. The test stays here permanently — regressions are caught automatically.
//!
//! Tests are named: `regression_<short_description>` or `regression_<ISSUE_ID>_<desc>`.

use iona::consensus::double_sign::{vote_guard_key, DoubleSignGuard};
use iona::crypto::PublicKeyBytes;
use iona::net::peer_score::{
    PeerScore, ViolationReason, BAN_THRESHOLD, PEER_MAX_PENDING_VALIDATIONS,
};
use iona::rpc_limits::{
    validate_batch_size, validate_body_size, validate_tx, RpcLimitResult, RpcLimiter,
    MAX_BODY_BYTES, SUBMIT_RATE_PER_SEC,
};
use iona::types::{Hash32, Tx};
use std::net::{IpAddr, Ipv4Addr};

// -----------------------------------------------------------------------------
// Constants
// -----------------------------------------------------------------------------

/// Test IP base network (192.168.1.0/24).
const TEST_IP_BASE_OCTET_1: u8 = 192;
const TEST_IP_BASE_OCTET_2: u8 = 168;
const TEST_IP_BASE_OCTET_3: u8 = 1;

/// Starting octets for different test IPs.
const IP_FLOOD_OCTET: u8 = 50;
const IP_INDEPENDENCE_A_OCTET: u8 = 60;
const IP_INDEPENDENCE_B_OCTET: u8 = 61;

/// Default transaction fields.
const VALID_CHAIN_ID: u64 = 1;
const VALID_NONCE: u64 = 0;
const VALID_GAS_LIMIT: u64 = 21_000;
const VALID_MAX_FEE: u64 = 1;
const VALID_PAYLOAD: &str = "ok";

/// Past nonce for replay protection test.
const CONFIRMED_NONCE: u64 = 10;
const PAST_NONCE: u64 = 5;

/// Hash bytes for test signatures.
const HASH_BYTE_A: u8 = 1;
const HASH_BYTE_B: u8 = 2;
const HASH_BYTE_C: u8 = 5;
const HASH_BYTE_D: u8 = 99;

/// Peer IDs for peer scoring tests.
const PEER_FLOOD_ID: &str = "peer-flood";
const PEER_ATTACK_ID: &str = "peer-attack";
const PEER_EVIL_ID: &str = "peer-evil";

/// Test seeds for double‑sign guard.
const GUARD_SEED_1: u8 = 10;
const GUARD_SEED_2: u8 = 11;
const GUARD_SEED_3: u8 = 12;

/// Double‑sign guard heights.
const DS_HEIGHT_1: u64 = 1;
const DS_HEIGHT_5: u64 = 5;

/// Double‑sign guard rounds.
const DS_ROUND_0: u32 = 0;

/// Flood multiplier.
const FLOOD_MULTIPLIER: usize = 10;

/// Batch size that exceeds limits.
const OVERSIZED_BATCH_SIZE: usize = 1_000_000;

// -----------------------------------------------------------------------------
// Helpers
// -----------------------------------------------------------------------------

/// Create a test IP address with the given last octet.
fn test_ip(octet: u8) -> IpAddr {
    IpAddr::V4(Ipv4Addr::new(TEST_IP_BASE_OCTET_1, TEST_IP_BASE_OCTET_2, TEST_IP_BASE_OCTET_3, octet))
}

/// Create a `Hash32` with a repeating byte.
fn hash(byte: u8) -> Hash32 {
    Hash32([byte; 32])
}

/// Create a minimal transaction with customisable fields.
fn tx(chain_id: u64, nonce: u64, gas_limit: u64, max_fee: u64, payload: &str) -> Tx {
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

/// Create a valid baseline transaction for tests that expect success.
fn valid_tx() -> Tx {
    tx(VALID_CHAIN_ID, VALID_NONCE, VALID_GAS_LIMIT, VALID_MAX_FEE, VALID_PAYLOAD)
}

// -----------------------------------------------------------------------------
// RPC surface regressions
// -----------------------------------------------------------------------------

/// REGRESSION: A transaction with zero `gas_limit` could pass validation and consume
/// block space without paying any fee (infinite gas‑price griefing).
/// Fixed: `validate_tx` now checks `gas_limit > 0`.
#[test]
fn regression_zero_gas_limit_rejected() {
    let result = validate_tx(&tx(VALID_CHAIN_ID, VALID_NONCE, 0, VALID_MAX_FEE, VALID_PAYLOAD), VALID_CHAIN_ID, VALID_NONCE);
    assert!(result.is_err(), "zero gas_limit must be rejected");
}

/// REGRESSION: A transaction with zero `max_fee` could pass validation and consume
/// block space for free.
/// Fixed: `validate_tx` now checks `max_fee_per_gas > 0`.
#[test]
fn regression_zero_max_fee_rejected() {
    let result = validate_tx(&tx(VALID_CHAIN_ID, VALID_NONCE, VALID_GAS_LIMIT, 0, VALID_PAYLOAD), VALID_CHAIN_ID, VALID_NONCE);
    assert!(result.is_err(), "zero max_fee_per_gas must be rejected");
}

/// REGRESSION: A transaction with a mismatched `chain_id` could be replayed on another
/// network (cross‑chain replay attack).
/// Fixed: `validate_tx` checks `chain_id` matches expected.
#[test]
fn regression_wrong_chain_id_rejected() {
    let result = validate_tx(&tx(9999, VALID_NONCE, VALID_GAS_LIMIT, VALID_MAX_FEE, VALID_PAYLOAD), VALID_CHAIN_ID, VALID_NONCE);
    assert!(
        result.is_err(),
        "wrong chain_id must be rejected (cross‑chain replay)"
    );
}

/// REGRESSION: A transaction with a past nonce (below confirmed) could cause a
/// double‑spend if the mempool accepted it.
/// Fixed: `validate_tx` rejects nonce < sender_nonce.
#[test]
fn regression_past_nonce_rejected() {
    // Confirmed nonce is `CONFIRMED_NONCE`, transaction nonce is `PAST_NONCE` → must reject.
    let result = validate_tx(&tx(VALID_CHAIN_ID, PAST_NONCE, VALID_GAS_LIMIT, VALID_MAX_FEE, VALID_PAYLOAD), VALID_CHAIN_ID, CONFIRMED_NONCE);
    assert!(
        result.is_err(),
        "past nonce must be rejected (replay protection)"
    );
}

/// REGRESSION: An oversized payload could cause unbounded memory allocation
/// during deserialisation.
/// Fixed: `validate_body_size` and `validate_tx` check payload length first.
#[test]
fn regression_oversized_payload_rejected() {
    let giant_payload = "x".repeat(MAX_BODY_BYTES + 1);
    let result = validate_tx(&tx(VALID_CHAIN_ID, VALID_NONCE, VALID_GAS_LIMIT, VALID_MAX_FEE, &giant_payload), VALID_CHAIN_ID, VALID_NONCE);
    assert!(result.is_err(), "oversized payload must be rejected");

    let body = vec![0u8; MAX_BODY_BYTES + 1];
    assert!(validate_body_size(&body, MAX_BODY_BYTES).is_err());
}

/// REGRESSION: A batch with too many items could exhaust CPU / memory.
/// Fixed: `validate_batch_size` enforces `MAX_BATCH_ITEMS`.
#[test]
fn regression_oversized_batch_rejected() {
    assert!(
        validate_batch_size(OVERSIZED_BATCH_SIZE).is_err(),
        "huge batch must be rejected"
    );
}

// -----------------------------------------------------------------------------
// Rate limiting regressions
// -----------------------------------------------------------------------------

/// REGRESSION: The rate limiter was not tracking violation streaks, so a flooder
/// could sustain attacks indefinitely at the burst rate.
/// Fixed: `violation_streak` is tracked and triggers quarantine.
#[test]
fn regression_flooder_eventually_quarantined() {
    let limiter = RpcLimiter::new();
    let peer = test_ip(IP_FLOOD_OCTET);
    let total_requests = SUBMIT_RATE_PER_SEC as usize * FLOOD_MULTIPLIER;
    for _ in 0..total_requests {
        limiter.check_submit(peer, "flood");
    }
    let result = limiter.check_submit(peer, "final");
    assert!(
        matches!(result, RpcLimitResult::RateLimited | RpcLimitResult::Blocked),
        "sustained flooder must be quarantined, got {result:?}"
    );
}

/// REGRESSION: Two different IP addresses were sharing rate‑limit state, allowing
/// IP spoofing to dilute the per‑IP limit.
/// Fixed: each IP has its own token bucket.
#[test]
fn regression_ip_buckets_are_independent() {
    let limiter = RpcLimiter::new();
    let ip_a = test_ip(IP_INDEPENDENCE_A_OCTET);
    let ip_b = test_ip(IP_INDEPENDENCE_B_OCTET);
    // Exhaust `ip_a` budget.
    for _ in 0..SUBMIT_RATE_PER_SEC {
        limiter.check_submit(ip_a, "req");
    }
    // `ip_b` must be unaffected.
    assert_eq!(
        limiter.check_submit(ip_b, "req"),
        RpcLimitResult::Allowed,
        "different IPs must have independent rate buckets"
    );
}

// -----------------------------------------------------------------------------
// P2P / peer score regressions
// -----------------------------------------------------------------------------

/// REGRESSION: A peer could send messages infinitely fast without being penalised,
/// enabling gossip flooding.
/// Fixed: `check_msg_quota()` enforces `PEER_MAX_MSGS_PER_SEC`.
#[test]
fn regression_peer_msg_flood_penalised() {
    use iona::net::peer_score::PEER_MAX_MSGS_PER_SEC;
    let mut score = PeerScore::with_defaults();
    let limit = PEER_MAX_MSGS_PER_SEC as usize;
    let mut rejected = 0;
    for _ in 0..(limit * 3) {
        if !score.check_msg_quota(PEER_FLOOD_ID) {
            rejected += 1;
        }
    }
    assert!(rejected > 0, "message flood must trigger quota rejections");
}

/// REGRESSION: A peer with a bad score was still allowed to submit more
/// pending validations, causing CPU exhaustion via validation queue.
/// Fixed: `acquire_validation_slot()` checks `PEER_MAX_PENDING_VALIDATIONS`.
#[test]
fn regression_peer_validation_slot_cap() {
    let mut score = PeerScore::with_defaults();
    for _ in 0..PEER_MAX_PENDING_VALIDATIONS {
        assert!(score.acquire_validation_slot(PEER_ATTACK_ID));
    }
    assert!(
        !score.acquire_validation_slot(PEER_ATTACK_ID),
        "peer must not exceed pending validation cap"
    );
}

/// REGRESSION: A permanently banned peer was still allowed to acquire
/// message quota tokens.
/// Fixed: `check_msg_quota` returns `false` for score ≤ ban threshold.
#[test]
fn regression_banned_peer_blocked_from_all_traffic() {
    let mut score = PeerScore::with_defaults();
    // Force ban.
    score.penalise_with(
        PEER_EVIL_ID,
        ViolationReason::InvalidBlock,
        BAN_THRESHOLD.unsigned_abs() as i64 + 50,
    );
    assert!(score.should_ban(PEER_EVIL_ID), "peer must be banned");
    assert!(
        !score.check_msg_quota(PEER_EVIL_ID),
        "banned peer must not pass message quota check"
    );
    assert!(
        !score.check_byte_quota(PEER_EVIL_ID, 1),
        "banned peer must not pass byte quota check"
    );
}

// -----------------------------------------------------------------------------
// Double‑sign guard regressions
// -----------------------------------------------------------------------------

/// REGRESSION: Running two validator instances with the same key could cause
/// equivocation — both sign different blocks at the same height and round.
/// Fixed: `DoubleSignGuard` persists records and refuses conflicting signs.
#[test]
fn regression_double_proposal_refused() {
    let dir = tempfile::tempdir().unwrap();
    let pk = PublicKeyBytes(vec![GUARD_SEED_1; 32]);
    let guard = DoubleSignGuard::new(dir.path().to_str().unwrap(), &pk).unwrap();

    guard.record_proposal(DS_HEIGHT_1, DS_ROUND_0, &hash(HASH_BYTE_B)).unwrap();
    let result = guard.check_proposal(DS_HEIGHT_1, DS_ROUND_0, &hash(HASH_BYTE_A));
    assert!(result.is_err(), "double‑proposal must be refused");
}

/// REGRESSION: After a crash‑restart, the guard state was not reloaded,
/// allowing a double‑sign on the first vote after restart.
/// Fixed: `DoubleSignGuard::new()` reloads from disk; `check` uses in‑memory and disk state.
#[test]
fn regression_guard_survives_restart() {
    let dir = tempfile::tempdir().unwrap();
    let pk = PublicKeyBytes(vec![GUARD_SEED_2; 32]);
    let path = dir.path().to_str().unwrap();

    // First instance: record a proposal.
    {
        let guard = DoubleSignGuard::new(path, &pk).unwrap();
        guard.record_proposal(DS_HEIGHT_5, DS_ROUND_0, &hash(HASH_BYTE_C)).unwrap();
    }

    // Second instance (simulates restart): must refuse conflicting proposal.
    {
        let guard = DoubleSignGuard::new(path, &pk).unwrap();
        let result = guard.check_proposal(DS_HEIGHT_5, DS_ROUND_0, &hash(HASH_BYTE_D));
        assert!(
            result.is_err(),
            "guard after restart must still refuse double‑proposal"
        );
    }
}

/// REGRESSION: The guard file could be silently rolled back to a previous
/// state by an attacker with filesystem access, allowing double‑sign.
/// Fixed: hash chain on every write; load verifies chain integrity.
#[test]
fn regression_rolled_back_guard_detected() {
    use std::fs;
    let dir = tempfile::tempdir().unwrap();
    let pk = PublicKeyBytes(vec![GUARD_SEED_3; 32]);
    let path = dir.path().to_str().unwrap();

    // Write a guard with a proposal.
    {
        let guard = DoubleSignGuard::new(path, &pk).unwrap();
        guard.record_proposal(DS_HEIGHT_1, DS_ROUND_0, &hash(HASH_BYTE_B)).unwrap();
    }

    // Read and corrupt the `chain_hash` (simulate rollback attack).
    let guard_file = format!(
        "{}/doublesign_{}.json",
        path,
        hex::encode([GUARD_SEED_3; 32])
    );
    let raw = fs::read_to_string(&guard_file).unwrap();
    let mut json: serde_json::Value = serde_json::from_str(&raw).unwrap();
    json["chain_hash"] = serde_json::json!("deadbeef");
    fs::write(&guard_file, serde_json::to_string(&json).unwrap()).unwrap();

    // Reload must fail.
    let result = DoubleSignGuard::new(path, &pk);
    assert!(
        result.is_err(),
        "corrupted / rolled‑back guard must be detected at load"
    );
}
