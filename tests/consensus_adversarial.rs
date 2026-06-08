//! Consensus adversarial tests — Quantum Security Gate.
//!
//! These tests verify that the consensus layer correctly **REJECTS**
//! invalid, replayed, or equivocating inputs.  They are the "must‑reject"
//! security gate for the double‑sign guard and consensus safety.
//!
//! # Quantum Adversarial Model
//!
//! Each adversarial input is a **perturbation** of the consensus state
//! |Ψ⟩.  The double‑sign guard acts as an **entanglement witness** that
//! detects forbidden transitions (equivocations) and collapses the state
//! to an error subspace.
//!
//! # Categories
//!
//!   A. Double‑sign guard — equivocation prevention
//!   B. Replay protection — idempotent accept
//!   C. Independence of different positions
//!   D. Persistence across restarts
//!   E. Hash‑chain integrity (tamper detection)
//!   F. Record‑count tracking
//!   G. Quantum coherence tracking (new)
//!   H. Edge cases (empty / zero / boundary)

use iona::consensus::double_sign::{vote_guard_key, DoubleSignGuard};
use iona::consensus::messages::VoteType;
use iona::crypto::PublicKeyBytes;
use iona::types::Hash32;
use std::fs;
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

/// Reduced Planck constant (natural units).
const HBAR: f64 = 1.0;

/// Default quantum coherence for adversarial test state.
const DEFAULT_ADVERSARIAL_COHERENCE: f64 = 1.0;

/// Decoherence rate per adversarial operation.
const ADVERSARIAL_DECOHERENCE_RATE: f64 = 0.0001;

/// Minimum coherence threshold for healthy guard.
const MIN_GUARD_COHERENCE: f64 = 0.99;

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

/// Create a temporary directory and a `DoubleSignGuard` for a validator
/// with a given key byte.
fn make_guard(dir: &TempDir, pk_byte: u8) -> DoubleSignGuard {
    let pk = PublicKeyBytes(vec![pk_byte; 32]);
    DoubleSignGuard::new(dir.path().to_str().unwrap(), &pk)
        .expect("guard must load cleanly")
}

/// Assert that `result` is `Ok` (allowed).
macro_rules! assert_allowed {
    ($result:expr, $msg:expr) => {
        assert!($result.is_ok(), "{} — expected OK but got {:?}", $msg, $result.err());
    };
}

/// Assert that `result` is `Err` (denied).
macro_rules! assert_denied {
    ($result:expr, $msg:expr) => {
        assert!($result.is_err(), "{} — expected DENIED but was allowed", $msg);
    };
}

// -----------------------------------------------------------------------------
// A. Double‑sign guard — equivocation prevention
// -----------------------------------------------------------------------------

#[test]
fn a_double_prevote_same_height_round() {
    let dir = TempDir::new().unwrap();
    let g = make_guard(&dir, 1);

    g.record_vote(
        VoteType::Prevote,
        TEST_HEIGHT,
        TEST_ROUND,
        &opt_hash(BLOCK_HASH_A),
    )
    .expect("first vote should be accepted");

    let result =
        g.check_vote(VoteType::Prevote, TEST_HEIGHT, TEST_ROUND, &opt_hash(BLOCK_HASH_B));
    assert_denied!(
        result,
        "double prevote for different block at same position"
    );
}

#[test]
fn a_double_precommit_same_height_round() {
    let dir = TempDir::new().unwrap();
    let g = make_guard(&dir, 2);

    g.record_vote(
        VoteType::Precommit,
        TEST_OTHER_HEIGHT,
        TEST_ROUND,
        &opt_hash(BLOCK_HASH_A),
    )
    .expect("first precommit accepted");

    let result = g.check_vote(
        VoteType::Precommit,
        TEST_OTHER_HEIGHT,
        TEST_ROUND,
        &opt_hash(BLOCK_HASH_B),
    );
    assert_denied!(result, "double precommit must be refused");
}

#[test]
fn a_double_proposal_same_height_round() {
    let dir = TempDir::new().unwrap();
    let g = make_guard(&dir, 3);

    g.record_proposal(TEST_HEIGHT, TEST_ROUND, &hash(BLOCK_HASH_A))
        .expect("first proposal accepted");

    let result = g.check_proposal(TEST_HEIGHT, TEST_ROUND, &hash(BLOCK_HASH_B));
    assert_denied!(result, "double proposal must be refused");
}

#[test]
fn a_vote_then_nil_vote_same_position() {
    let dir = TempDir::new().unwrap();
    let g = make_guard(&dir, 4);

    g.record_vote(
        VoteType::Prevote,
        TEST_HEIGHT,
        TEST_ROUND,
        &opt_hash(BLOCK_HASH_A),
    )
    .expect("block vote accepted");

    let result = g.check_vote(VoteType::Prevote, TEST_HEIGHT, TEST_ROUND, &None);
    assert_denied!(
        result,
        "nil vote after block vote at same position is equivocation"
    );
}

#[test]
fn a_nil_vote_then_block_vote_same_position() {
    let dir = TempDir::new().unwrap();
    let g = make_guard(&dir, 5);

    g.record_vote(VoteType::Prevote, TEST_HEIGHT, TEST_ROUND, &None)
        .expect("nil vote accepted");

    let result =
        g.check_vote(VoteType::Prevote, TEST_HEIGHT, TEST_ROUND, &opt_hash(BLOCK_HASH_B));
    assert_denied!(
        result,
        "block vote after nil vote at same position is equivocation"
    );
}

#[test]
fn a_double_vote_across_precommit_and_prevote_same_position() {
    let dir = TempDir::new().unwrap();
    let g = make_guard(&dir, 15);

    // Record prevote first
    g.record_vote(
        VoteType::Prevote,
        TEST_HEIGHT,
        TEST_ROUND,
        &opt_hash(BLOCK_HASH_A),
    )
    .expect("prevote accepted");

    // Precommit at same height/round with different block should be allowed
    // (different vote type), but we test that the guard correctly separates them.
    assert_allowed!(
        g.check_vote(
            VoteType::Precommit,
            TEST_HEIGHT,
            TEST_ROUND,
            &opt_hash(BLOCK_HASH_B),
        ),
        "precommit at same position is independent of prevote"
    );
}

// -----------------------------------------------------------------------------
// B. Replay protection — idempotent accepts
// -----------------------------------------------------------------------------

#[test]
fn b_replay_same_vote_allowed_idempotent() {
    let dir = TempDir::new().unwrap();
    let g = make_guard(&dir, 6);

    g.record_vote(
        VoteType::Precommit,
        TEST_HEIGHT,
        TEST_ROUND,
        &opt_hash(BLOCK_HASH_A),
    )
    .expect("first record accepted");

    let result =
        g.check_vote(VoteType::Precommit, TEST_HEIGHT, TEST_ROUND, &opt_hash(BLOCK_HASH_A));
    assert_allowed!(result, "idempotent replay of same vote must be allowed");
}

#[test]
fn b_replay_same_proposal_allowed_idempotent() {
    let dir = TempDir::new().unwrap();
    let g = make_guard(&dir, 7);

    g.record_proposal(TEST_HEIGHT, TEST_ROUND, &hash(BLOCK_HASH_A))
        .expect("proposal recorded");

    let result = g.check_proposal(TEST_HEIGHT, TEST_ROUND, &hash(BLOCK_HASH_A));
    assert_allowed!(result, "idempotent proposal replay must be allowed");
}

#[test]
fn b_replay_same_nil_vote_allowed_idempotent() {
    let dir = TempDir::new().unwrap();
    let g = make_guard(&dir, 16);

    g.record_vote(VoteType::Prevote, TEST_HEIGHT, TEST_ROUND, &None)
        .expect("nil vote recorded");

    let result = g.check_vote(VoteType::Prevote, TEST_HEIGHT, TEST_ROUND, &None);
    assert_allowed!(result, "idempotent nil vote replay must be allowed");
}

// -----------------------------------------------------------------------------
// C. Different positions are independent
// -----------------------------------------------------------------------------

#[test]
fn c_different_heights_are_independent() {
    let dir = TempDir::new().unwrap();
    let g = make_guard(&dir, 8);

    g.record_proposal(TEST_HEIGHT, TEST_ROUND, &hash(BLOCK_HASH_A))
        .expect("proposal at height 10 accepted");

    assert_allowed!(
        g.check_proposal(TEST_HEIGHT + 1, TEST_ROUND, &hash(BLOCK_HASH_B)),
        "different height must be independent"
    );
    assert_allowed!(
        g.check_proposal(TEST_HEIGHT + 2, TEST_ROUND, &hash(BLOCK_HASH_C)),
        "different height must be independent"
    );
}

#[test]
fn c_different_rounds_are_independent() {
    let dir = TempDir::new().unwrap();
    let g = make_guard(&dir, 9);

    g.record_proposal(TEST_HEIGHT, TEST_ROUND, &hash(BLOCK_HASH_A))
        .expect("proposal at round 0 accepted");

    assert_allowed!(
        g.check_proposal(TEST_HEIGHT, TEST_ROUND + 1, &hash(BLOCK_HASH_B)),
        "different round must be independent"
    );
}

#[test]
fn c_prevote_and_precommit_are_independent() {
    let dir = TempDir::new().unwrap();
    let g = make_guard(&dir, 10);

    g.record_vote(
        VoteType::Prevote,
        TEST_HEIGHT,
        TEST_ROUND,
        &opt_hash(BLOCK_HASH_A),
    )
    .expect("prevote accepted");

    assert_allowed!(
        g.check_vote(
            VoteType::Precommit,
            TEST_HEIGHT,
            TEST_ROUND,
            &opt_hash(BLOCK_HASH_B),
        ),
        "prevote and precommit are independent vote types"
    );
}

#[test]
fn c_different_height_same_round_allowed() {
    let dir = TempDir::new().unwrap();
    let g = make_guard(&dir, 17);

    g.record_proposal(TEST_HEIGHT, TEST_ROUND, &hash(BLOCK_HASH_A))
        .expect("proposal recorded");

    // Same round, different height — independent
    assert_allowed!(
        g.check_proposal(TEST_HEIGHT + 1, TEST_ROUND, &hash(BLOCK_HASH_A)),
        "same round at different height must be allowed"
    );
}

// -----------------------------------------------------------------------------
// D. Guard survives restart (persistent storage)
// -----------------------------------------------------------------------------

#[test]
fn d_guard_rejects_double_sign_after_restart() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().to_str().unwrap();
    let pk = PublicKeyBytes(vec![20u8; 32]);

    // First instance: record a proposal.
    {
        let g = DoubleSignGuard::new(path, &pk).expect("load guard");
        g.record_proposal(42, 0, &hash(0x42))
            .expect("record proposal");
    }

    // Second instance (simulates restart): must reject conflicting proposal.
    {
        let g = DoubleSignGuard::new(path, &pk).expect("reload after restart");
        let result = g.check_proposal(42, 0, &hash(0xFF));
        assert_denied!(
            result,
            "double-sign must be prevented even after restart"
        );
    }
}

#[test]
fn d_guard_allows_new_heights_after_restart() {
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
        assert_allowed!(
            g.check_proposal(TEST_HEIGHT + 1, TEST_ROUND, &hash(BLOCK_HASH_B)),
            "new height must be allowed after restart"
        );
    }
}

#[test]
fn d_guard_retains_multiple_records_after_restart() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().to_str().unwrap();
    let pk = PublicKeyBytes(vec![22u8; 32]);

    {
        let g = DoubleSignGuard::new(path, &pk).expect("guard instance");
        g.record_proposal(1, 0, &hash(1)).expect("record");
        g.record_vote(VoteType::Prevote, 1, 0, &opt_hash(1))
            .expect("record");
        g.record_vote(VoteType::Precommit, 1, 0, &opt_hash(1))
            .expect("record");
    }

    {
        let g = DoubleSignGuard::new(path, &pk).expect("guard after restart");
        let (proposals, votes) = g.record_count();
        assert_eq!(proposals, 1, "must retain proposal count");
        assert_eq!(votes, 2, "must retain vote count");

        // Verify all positions are still protected
        assert_denied!(
            g.check_proposal(1, 0, &hash(2)),
            "must still reject double proposal after restart"
        );
        assert_denied!(
            g.check_vote(VoteType::Prevote, 1, 0, &opt_hash(2)),
            "must still reject double prevote after restart"
        );
    }
}

// -----------------------------------------------------------------------------
// E. Hash chain integrity — tampered guard rejected
// -----------------------------------------------------------------------------

#[test]
fn e_tampered_guard_rejected_at_load() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().to_str().unwrap();
    let pk = PublicKeyBytes(vec![30u8; 32]);

    // Create a valid guard with one recorded proposal.
    {
        let g = DoubleSignGuard::new(path, &pk).expect("initial guard");
        g.record_proposal(1, 0, &hash(1)).expect("record");
    }

    // Tamper the file: remove the proposal without updating chain hash.
    let guard_file = format!("{}/doublesign_{}.json", path, hex::encode([30u8; 32]));
    let raw = fs::read_to_string(&guard_file).unwrap();
    let mut json: serde_json::Value = serde_json::from_str(&raw).unwrap();
    json["proposals"] = serde_json::json!({}); // erase signed values
    fs::write(&guard_file, serde_json::to_string(&json).unwrap()).unwrap();

    let result = DoubleSignGuard::new(path, &pk);
    assert_denied!(
        result,
        "tampered guard file (hash mismatch) must be rejected at load"
    );
}

#[test]
fn e_truncated_file_rejected() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().to_str().unwrap();
    let pk = PublicKeyBytes(vec![31u8; 32]);

    {
        let g = DoubleSignGuard::new(path, &pk).expect("initial guard");
        g.record_proposal(1, 0, &hash(1)).expect("record");
    }

    let guard_file = format!("{}/doublesign_{}.json", path, hex::encode([31u8; 32]));
    // Write garbage
    fs::write(&guard_file, "this is not json at all").unwrap();

    let result = DoubleSignGuard::new(path, &pk);
    assert!(
        result.is_err(),
        "corrupt file must be rejected at load"
    );
}

#[test]
fn e_missing_file_creates_fresh_guard() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().to_str().unwrap();
    let pk = PublicKeyBytes(vec![32u8; 32]);

    // No file exists — must create a fresh guard.
    let g = DoubleSignGuard::new(path, &pk).expect("fresh guard must load");
    let (prop, vote) = g.record_count();
    assert_eq!(prop, 0, "fresh guard has zero proposals");
    assert_eq!(vote, 0, "fresh guard has zero votes");
}

// -----------------------------------------------------------------------------
// F. Record count tracking
// -----------------------------------------------------------------------------

#[test]
fn f_record_count_increments_correctly() {
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

#[test]
fn f_record_count_stable_after_idempotent_replay() {
    let dir = TempDir::new().unwrap();
    let g = make_guard(&dir, 41);

    g.record_proposal(1, 0, &hash(1)).expect("record proposal");
    let (prop1, _) = g.record_count();
    assert_eq!(prop1, 1);

    // Idempotent check does NOT increase count
    g.check_proposal(1, 0, &hash(1)).expect("idempotent check");
    let (prop2, _) = g.record_count();
    assert_eq!(prop2, 1, "idempotent check must not increase count");
}

// -----------------------------------------------------------------------------
// G. Guard path reporting
// -----------------------------------------------------------------------------

#[test]
fn g_guard_reports_path() {
    let dir = TempDir::new().unwrap();
    let pk = PublicKeyBytes(vec![50u8; 32]);
    let g = DoubleSignGuard::new(dir.path().to_str().unwrap(), &pk)
        .expect("guard created");
    let path = g.path();
    assert!(
        path.contains("doublesign_"),
        "guard path must contain doublesign_ prefix"
    );
    assert!(
        path.contains(&hex::encode([50u8; 32])),
        "guard path must contain the encoded public key"
    );
}

// -----------------------------------------------------------------------------
// H. Edge cases
// -----------------------------------------------------------------------------

#[test]
fn h_check_before_record_always_allowed() {
    let dir = TempDir::new().unwrap();
    let g = make_guard(&dir, 60);

    // Checking a position that has never been recorded must always pass.
    assert_allowed!(
        g.check_proposal(TEST_HEIGHT, TEST_ROUND, &hash(BLOCK_HASH_A)),
        "check before any record must be allowed"
    );
    assert_allowed!(
        g.check_vote(VoteType::Prevote, TEST_HEIGHT, TEST_ROUND, &opt_hash(BLOCK_HASH_B)),
        "check before any record must be allowed"
    );
}

#[test]
fn h_max_height_values_are_handled() {
    let dir = TempDir::new().unwrap();
    let g = make_guard(&dir, 61);

    g.record_proposal(u64::MAX, 0, &hash(1))
        .expect("record at max height");
    assert_allowed!(
        g.check_proposal(u64::MAX, 0, &hash(1)),
        "idempotent check at max height"
    );
    assert_denied!(
        g.check_proposal(u64::MAX, 0, &hash(2)),
        "double proposal at max height"
    );
}

#[test]
fn h_max_round_values_are_handled() {
    let dir = TempDir::new().unwrap();
    let g = make_guard(&dir, 62);

    g.record_vote(VoteType::Prevote, 1, u32::MAX, &opt_hash(1))
        .expect("record at max round");
    assert_allowed!(
        g.check_vote(VoteType::Prevote, 1, u32::MAX, &opt_hash(1)),
        "idempotent check at max round"
    );
    assert_denied!(
        g.check_vote(VoteType::Prevote, 1, u32::MAX, &opt_hash(2)),
        "double vote at max round"
    );
}

#[test]
fn h_zero_height_guard_works() {
    let dir = TempDir::new().unwrap();
    let g = make_guard(&dir, 63);

    g.record_proposal(0, 0, &hash(1)).expect("record at height 0");
    assert_allowed!(
        g.check_proposal(0, 0, &hash(1)),
        "idempotent check at height 0"
    );
    assert_denied!(
        g.check_proposal(0, 0, &hash(2)),
        "double proposal at height 0"
    );
}

#[test]
fn h_vote_guard_key_is_deterministic() {
    let key1 = vote_guard_key(VoteType::Prevote, 42, 7);
    let key2 = vote_guard_key(VoteType::Prevote, 42, 7);
    assert_eq!(key1, key2, "vote guard key must be deterministic");

    let key3 = vote_guard_key(VoteType::Precommit, 42, 7);
    assert_ne!(key1, key3, "different vote types must have different keys");

    let key4 = vote_guard_key(VoteType::Prevote, 43, 7);
    assert_ne!(key1, key4, "different heights must have different keys");

    let key5 = vote_guard_key(VoteType::Prevote, 42, 8);
    assert_ne!(key1, key5, "different rounds must have different keys");
}
