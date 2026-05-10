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
use tempfile::TempDir;

// -----------------------------------------------------------------------------
// Constants
// -----------------------------------------------------------------------------

const TEST_HEIGHT: u64 = 10;
const TEST_ROUND: u32 = 0;
const TEST_OTHER_HEIGHT: u64 = 7;
const TEST_OTHER_ROUND: u32 = 1;

const BLOCK_HASH_A: u8 = 0xAA;
const BLOCK_HASH_B: u8 = 0xBB;
const BLOCK_HASH_C: u8 = 0xCC;

// -----------------------------------------------------------------------------
// Helpers
// -----------------------------------------------------------------------------

/// Create a `Hash32` with a repeating byte.
fn hash(byte: u8) -> Hash32 {
    Hash32([byte; 32])
}

/// Optional hash (Some or None).
fn opt_hash(byte: u8) -> Option<Hash32> {
    Some(hash(byte))
}

/// Create a temporary directory and a `DoubleSignGuard` for a validator with a given key byte.
fn make_guard(dir: &TempDir, pk_byte: u8) -> DoubleSignGuard {
    let pk = PublicKeyBytes(vec![pk_byte; 32]);
    DoubleSignGuard::new(dir.path().to_str().unwrap(), &pk)
        .expect("guard must load cleanly")
}

// -----------------------------------------------------------------------------
// A. Double‑sign guard — equivocation prevention
// -----------------------------------------------------------------------------

#[test]
fn adversarial_double_prevote_same_height_round() {
    let dir = TempDir::new().unwrap();
    let g = make_guard(&dir, 1);
    g.record_vote(VoteType::Prevote, TEST_HEIGHT, TEST_ROUND, &opt_hash(BLOCK_HASH_A))
        .expect("first vote should be accepted");
    let result = g.check_vote(VoteType::Prevote, TEST_HEIGHT, TEST_ROUND, &opt_hash(BLOCK_HASH_B));
    assert!(
        result.is_err(),
        "double prevote for different block at same position must be refused"
    );
}

#[test]
fn adversarial_double_precommit_same_height_round() {
    let dir = TempDir::new().unwrap();
    let g = make_guard(&dir, 2);
    g.record_vote(VoteType::Precommit, TEST_OTHER_HEIGHT, TEST_ROUND, &opt_hash(BLOCK_HASH_A))
        .expect("first precommit accepted");
    let result = g.check_vote(
        VoteType::Precommit,
        TEST_OTHER_HEIGHT,
        TEST_ROUND,
        &opt_hash(BLOCK_HASH_B),
    );
    assert!(result.is_err(), "double precommit must be refused");
}

#[test]
fn adversarial_double_proposal_same_height_round() {
    let dir = TempDir::new().unwrap();
    let g = make_guard(&dir, 3);
    g.record_proposal(TEST_HEIGHT, TEST_ROUND, &hash(BLOCK_HASH_A))
        .expect("first proposal accepted");
    let result = g.check_proposal(TEST_HEIGHT, TEST_ROUND, &hash(BLOCK_HASH_B));
    assert!(result.is_err(), "double proposal must be refused");
}

#[test]
fn adversarial_vote_then_nil_vote_same_position() {
    let dir = TempDir::new().unwrap();
    let g = make_guard(&dir, 4);
    g.record_vote(VoteType::Prevote, TEST_HEIGHT, TEST_ROUND, &opt_hash(BLOCK_HASH_A))
        .expect("block vote accepted");
    let result = g.check_vote(VoteType::Prevote, TEST_HEIGHT, TEST_ROUND, &None);
    assert!(
        result.is_err(),
        "nil vote after block vote at same position is equivocation"
    );
}

#[test]
fn adversarial_nil_vote_then_block_vote_same_position() {
    let dir = TempDir::new().unwrap();
    let g = make_guard(&dir, 5);
    g.record_vote(VoteType::Prevote, TEST_HEIGHT, TEST_ROUND, &None)
        .expect("nil vote accepted");
    let result = g.check_vote(VoteType::Prevote, TEST_HEIGHT, TEST_ROUND, &opt_hash(BLOCK_HASH_B));
    assert!(
        result.is_err(),
        "block vote after nil vote at same position is equivocation"
    );
}

// -----------------------------------------------------------------------------
// B. Replay protection — idempotent accepts
// -----------------------------------------------------------------------------

#[test]
fn replay_same_vote_allowed_idempotent() {
    let dir = TempDir::new().unwrap();
    let g = make_guard(&dir, 6);
    g.record_vote(VoteType::Precommit, TEST_HEIGHT, TEST_ROUND, &opt_hash(BLOCK_HASH_A))
        .expect("first record accepted");
    let result = g.check_vote(VoteType::Precommit, TEST_HEIGHT, TEST_ROUND, &opt_hash(BLOCK_HASH_A));
    assert!(
        result.is_ok(),
        "idempotent replay of same vote must be allowed"
    );
}

#[test]
fn replay_same_proposal_allowed_idempotent() {
    let dir = TempDir::new().unwrap();
    let g = make_guard(&dir, 7);
    g.record_proposal(TEST_HEIGHT, TEST_ROUND, &hash(BLOCK_HASH_A))
        .expect("proposal recorded");
    let result = g.check_proposal(TEST_HEIGHT, TEST_ROUND, &hash(BLOCK_HASH_A));
    assert!(result.is_ok(), "idempotent proposal replay must be allowed");
}

// -----------------------------------------------------------------------------
// C. Different positions are independent
// -----------------------------------------------------------------------------

#[test]
fn different_heights_are_independent() {
    let dir = TempDir::new().unwrap();
    let g = make_guard(&dir, 8);
    g.record_proposal(TEST_HEIGHT, TEST_ROUND, &hash(BLOCK_HASH_A))
        .expect("proposal at height 10 accepted");
    assert!(g
        .check_proposal(TEST_HEIGHT + 1, TEST_ROUND, &hash(BLOCK_HASH_B))
        .is_ok());
    assert!(g
        .check_proposal(TEST_HEIGHT + 2, TEST_ROUND, &hash(BLOCK_HASH_C))
        .is_ok());
}

#[test]
fn different_rounds_are_independent() {
    let dir = TempDir::new().unwrap();
    let g = make_guard(&dir, 9);
    g.record_proposal(TEST_HEIGHT, TEST_ROUND, &hash(BLOCK_HASH_A))
        .expect("proposal at round 0 accepted");
    assert!(g
        .check_proposal(TEST_HEIGHT, TEST_ROUND + 1, &hash(BLOCK_HASH_B))
        .is_ok());
}

#[test]
fn prevote_and_precommit_are_independent() {
    let dir = TempDir::new().unwrap();
    let g = make_guard(&dir, 10);
    g.record_vote(VoteType::Prevote, TEST_HEIGHT, TEST_ROUND, &opt_hash(BLOCK_HASH_A))
        .expect("prevote accepted");
    assert!(g
        .check_vote(VoteType::Precommit, TEST_HEIGHT, TEST_ROUND, &opt_hash(BLOCK_HASH_B))
        .is_ok());
}

// -----------------------------------------------------------------------------
// D. Guard survives restart (persistent storage)
// -----------------------------------------------------------------------------

#[test]
fn guard_rejects_double_sign_after_restart() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().to_str().unwrap();
    let pk = PublicKeyBytes(vec![20u8; 32]);

    // First instance: record a proposal.
    {
        let g = DoubleSignGuard::new(path, &pk).expect("load guard");
        g.record_proposal(42, 0, &hash(0x42))
            .expect("record proposal");
    }

    // Second instance (simulates restart): must reject conflicting proposal at same height/round.
    {
        let g = DoubleSignGuard::new(path, &pk).expect("reload after restart");
        let result = g.check_proposal(42, 0, &hash(0xFF));
        assert!(
            result.is_err(),
            "double-sign must be prevented even after restart"
        );
    }
}

#[test]
fn guard_allows_new_heights_after_restart() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().to_str().unwrap();
    let pk = PublicKeyBytes(vec![21u8; 32]);

    {
        let g = DoubleSignGuard::new(path, &pk).expect("guard instance");
        g.record_proposal(TEST_HEIGHT, TEST_ROUND, &hash(BLOCK_HASH_A))
            .expect("record proposal");
    }

    {
        let g = DoubleSignGuard::new(path, &pk).expect("guard after restart");
        assert!(g
            .check_proposal(TEST_HEIGHT + 1, TEST_ROUND, &hash(BLOCK_HASH_B))
            .is_ok());
    }
}

// -----------------------------------------------------------------------------
// E. Hash chain integrity — tampered guard rejected
// -----------------------------------------------------------------------------

#[test]
fn tampered_guard_rejected_at_load() {
    use std::fs;

    let dir = TempDir::new().unwrap();
    let path = dir.path().to_str().unwrap();
    let pk = PublicKeyBytes(vec![30u8; 32]);

    // Create a valid guard with one recorded proposal.
    {
        let g = DoubleSignGuard::new(path, &pk).expect("initial guard");
        g.record_proposal(1, 0, &hash(1)).expect("record");
    }

    // Tamper the file: remove the proposal without updating chain hash.
    let guard_file = format!(
        "{}/doublesign_{}.json",
        path,
        hex::encode([30u8; 32])
    );
    let raw = fs::read_to_string(&guard_file).unwrap();
    let mut json: serde_json::Value = serde_json::from_str(&raw).unwrap();
    json["proposals"] = serde_json::json!({}); // erase signed values
    fs::write(&guard_file, serde_json::to_string(&json).unwrap()).unwrap();

    let result = DoubleSignGuard::new(path, &pk);
    assert!(
        result.is_err(),
        "tampered guard file (hash mismatch) must be rejected at load"
    );
}

// -----------------------------------------------------------------------------
// F. Record count tracking
// -----------------------------------------------------------------------------

#[test]
fn record_count_increments_correctly() {
    let dir = TempDir::new().unwrap();
    let g = make_guard(&dir, 40);
    let (prop0, vote0) = g.record_count();
    assert_eq!(prop0, 0);
    assert_eq!(vote0, 0);

    g.record_proposal(1, 0, &hash(1)).expect("record proposal");
    let (prop1, _) = g.record_count();
    assert_eq!(prop1, 1);

    g.record_vote(VoteType::Prevote, 1, 0, &opt_hash(1))
        .expect("record prevote");
    g.record_vote(VoteType::Precommit, 1, 0, &opt_hash(1))
        .expect("record precommit");
    let (_, vote2) = g.record_count();
    assert_eq!(vote2, 2);
}
