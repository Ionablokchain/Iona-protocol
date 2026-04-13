//! Consensus adversarial tests.
//!
//! These tests verify that the consensus layer correctly REJECTS invalid,
//! replayed, or equivocating inputs — they are "must reject" tests.
//!
//! Categories:
//!   A. Double-sign guard — equivocation prevention
//!   B. Replay protection — same message reused
//!   C. Invalid proposer detection
//!   D. Consensus safety invariants under adversarial input
//!   E. Evidence handling (DoS-safe)

use iona::consensus::double_sign::{vote_guard_key, DoubleSignGuard};
use iona::consensus::messages::VoteType;
use iona::crypto::PublicKeyBytes;
use iona::types::Hash32;

fn hash(b: u8) -> Hash32 {
    Hash32([b; 32])
}
fn opt_hash(b: u8) -> Option<Hash32> {
    Some(hash(b))
}

fn make_guard(dir: &tempfile::TempDir, pk_byte: u8) -> DoubleSignGuard {
    let pk = PublicKeyBytes(vec![pk_byte; 32]);
    DoubleSignGuard::new(dir.path().to_str().unwrap(), &pk).expect("guard must load cleanly")
}

// ── A. Double-sign guard ──────────────────────────────────────────────────

#[test]
fn adversarial_double_prevote_same_height_round() {
    let dir = tempfile::tempdir().unwrap();
    let g = make_guard(&dir, 1);
    // Sign prevote for block A.
    g.record_vote(VoteType::Prevote, 10, 0, &opt_hash(0xAA))
        .unwrap();
    // Attempt prevote for block B at same position → must fail.
    let result = g.check_vote(VoteType::Prevote, 10, 0, &opt_hash(0xBB));
    assert!(
        result.is_err(),
        "double prevote for different block must be refused"
    );
}

#[test]
fn adversarial_double_precommit_same_height_round() {
    let dir = tempfile::tempdir().unwrap();
    let g = make_guard(&dir, 2);
    g.record_vote(VoteType::Precommit, 7, 1, &opt_hash(0x11))
        .unwrap();
    let result = g.check_vote(VoteType::Precommit, 7, 1, &opt_hash(0x22));
    assert!(result.is_err(), "double precommit must be refused");
}

#[test]
fn adversarial_double_proposal_same_height_round() {
    let dir = tempfile::tempdir().unwrap();
    let g = make_guard(&dir, 3);
    g.record_proposal(5, 0, &hash(0x01)).unwrap();
    let result = g.check_proposal(5, 0, &hash(0x02));
    assert!(result.is_err(), "double proposal must be refused");
}

#[test]
fn adversarial_vote_then_nil_vote_same_position() {
    let dir = tempfile::tempdir().unwrap();
    let g = make_guard(&dir, 4);
    // Record a prevote for a block.
    g.record_vote(VoteType::Prevote, 3, 0, &opt_hash(0x55))
        .unwrap();
    // Now attempt a nil prevote at same position — this is equivocation.
    let result = g.check_vote(VoteType::Prevote, 3, 0, &None);
    assert!(
        result.is_err(),
        "nil vote after block vote at same position is equivocation"
    );
}

#[test]
fn adversarial_nil_vote_then_block_vote_same_position() {
    let dir = tempfile::tempdir().unwrap();
    let g = make_guard(&dir, 5);
    g.record_vote(VoteType::Prevote, 3, 0, &None).unwrap();
    let result = g.check_vote(VoteType::Prevote, 3, 0, &opt_hash(0x77));
    assert!(
        result.is_err(),
        "block vote after nil at same position is equivocation"
    );
}

// ── B. Replay protection ──────────────────────────────────────────────────

#[test]
fn replay_same_vote_allowed_idempotent() {
    // The same vote replayed (exactly the same block_id) must be accepted
    // (idempotent replay = safe, allows network retransmission).
    let dir = tempfile::tempdir().unwrap();
    let g = make_guard(&dir, 6);
    g.record_vote(VoteType::Precommit, 1, 0, &opt_hash(0xAA))
        .unwrap();
    // Exact same vote replayed — must be OK.
    let result = g.check_vote(VoteType::Precommit, 1, 0, &opt_hash(0xAA));
    assert!(
        result.is_ok(),
        "idempotent replay of same vote must be allowed"
    );
}

#[test]
fn replay_same_proposal_allowed_idempotent() {
    let dir = tempfile::tempdir().unwrap();
    let g = make_guard(&dir, 7);
    g.record_proposal(2, 0, &hash(0xBB)).unwrap();
    let result = g.check_proposal(2, 0, &hash(0xBB));
    assert!(result.is_ok(), "idempotent proposal replay must be allowed");
}

// ── C. Different positions are independent ────────────────────────────────

#[test]
fn different_heights_are_independent() {
    let dir = tempfile::tempdir().unwrap();
    let g = make_guard(&dir, 8);
    g.record_proposal(1, 0, &hash(1)).unwrap();
    // Height 2 is independent — can sign any block.
    assert!(g.check_proposal(2, 0, &hash(2)).is_ok());
    assert!(g.check_proposal(2, 0, &hash(99)).is_ok());
}

#[test]
fn different_rounds_are_independent() {
    let dir = tempfile::tempdir().unwrap();
    let g = make_guard(&dir, 9);
    g.record_proposal(1, 0, &hash(0xAA)).unwrap();
    // Round 1 of same height is independent.
    assert!(g.check_proposal(1, 1, &hash(0xBB)).is_ok());
}

#[test]
fn prevote_and_precommit_are_independent() {
    let dir = tempfile::tempdir().unwrap();
    let g = make_guard(&dir, 10);
    // Prevote for block A.
    g.record_vote(VoteType::Prevote, 5, 0, &opt_hash(0xAA))
        .unwrap();
    // Precommit for block B at same position is a different vote type — fine.
    assert!(g
        .check_vote(VoteType::Precommit, 5, 0, &opt_hash(0xBB))
        .is_ok());
}

// ── D. Guard survives restart ─────────────────────────────────────────────

#[test]
fn guard_rejects_double_sign_after_restart() {
    let dir = tempfile::tempdir().unwrap();
    let pk = PublicKeyBytes(vec![20u8; 32]);
    let path = dir.path().to_str().unwrap();

    // Instance 1: sign a proposal.
    {
        let g = DoubleSignGuard::new(path, &pk).unwrap();
        g.record_proposal(42, 0, &hash(0x42)).unwrap();
    }

    // Instance 2 (crash-restart): must still refuse conflicting proposal.
    {
        let g = DoubleSignGuard::new(path, &pk).unwrap();
        let result = g.check_proposal(42, 0, &hash(0xFF));
        assert!(
            result.is_err(),
            "double-sign must be prevented even after restart"
        );
    }
}

#[test]
fn guard_allows_new_heights_after_restart() {
    let dir = tempfile::tempdir().unwrap();
    let pk = PublicKeyBytes(vec![21u8; 32]);
    let path = dir.path().to_str().unwrap();

    {
        let g = DoubleSignGuard::new(path, &pk).unwrap();
        g.record_proposal(1, 0, &hash(1)).unwrap();
    }

    {
        let g = DoubleSignGuard::new(path, &pk).unwrap();
        // Height 2 was never signed — must be allowed.
        assert!(g.check_proposal(2, 0, &hash(2)).is_ok());
    }
}

// ── E. Hash chain integrity ────────────────────────────────────────────────

#[test]
fn tampered_guard_rejected_at_load() {
    use std::fs;
    let dir = tempfile::tempdir().unwrap();
    let pk = PublicKeyBytes(vec![30u8; 32]);
    let path_str = dir.path().to_str().unwrap();

    {
        let g = DoubleSignGuard::new(path_str, &pk).unwrap();
        g.record_proposal(1, 0, &hash(1)).unwrap();
    }

    // Tamper: alter the proposals map without updating chain_hash.
    let guard_file = format!("{}/doublesign_{}.json", path_str, hex::encode([30u8; 32]));
    let raw = fs::read_to_string(&guard_file).unwrap();
    let mut json: serde_json::Value = serde_json::from_str(&raw).unwrap();
    json["proposals"] = serde_json::json!({}); // erase proposals (rollback attack)
    fs::write(&guard_file, serde_json::to_string(&json).unwrap()).unwrap();

    let result = DoubleSignGuard::new(path_str, &pk);
    assert!(
        result.is_err(),
        "tampered guard file (hash mismatch) must be rejected at load"
    );
}

// ── F. Record count ────────────────────────────────────────────────────────

#[test]
fn record_count_increments_correctly() {
    let dir = tempfile::tempdir().unwrap();
    let g = make_guard(&dir, 40);
    let (p0, v0) = g.record_count();
    assert_eq!(p0, 0);
    assert_eq!(v0, 0);

    g.record_proposal(1, 0, &hash(1)).unwrap();
    let (p1, _) = g.record_count();
    assert_eq!(p1, 1);

    g.record_vote(VoteType::Prevote, 1, 0, &opt_hash(1))
        .unwrap();
    g.record_vote(VoteType::Precommit, 1, 0, &opt_hash(1))
        .unwrap();
    let (_, v2) = g.record_count();
    assert_eq!(v2, 2);
}
