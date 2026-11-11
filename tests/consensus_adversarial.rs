//! Consensus adversarial tests — Double-sign guard.
//!
//! These tests are the "must-reject" security gate for the double-sign
//! guard used by the consensus layer. They assert that the guard
//! **rejects** equivocation, conflicting inputs, and tampered on-disk
//! state, while remaining idempotent for exact replays and independent
//! across distinct consensus positions.
//!
//! # Threat model
//!
//! A Byzantine validator (or a buggy honest one) may attempt to:
//!
//! * sign two conflicting proposals at the same `(height, round)`;
//! * sign two conflicting prevotes or precommits at the same
//!   `(height, round)`;
//! * flip between a block vote and a `nil` vote at the same position;
//! * replay a previously accepted vote hoping it bypasses the guard;
//! * tamper with the on-disk guard file to erase or rewrite prior
//!   signatures.
//!
//! The guard MUST prevent every one of those, while allowing:
//!
//! * exact replays of an already-recorded vote or proposal
//!   (idempotent accept);
//! * votes / proposals at different heights or rounds;
//! * a prevote and a precommit at the same position (they are
//!   distinct vote types).
//!
//! # Categories
//!
//! * **A** — Double-sign guard: equivocation prevention
//! * **B** — Replay protection: idempotent accept
//! * **C** — Independence of different positions
//! * **D** — Persistence across restarts
//! * **E** — Hash-chain integrity: tamper detection
//! * **F** — Record-count tracking
//! * **G** — Guard path reporting
//! * **H** — Edge cases: empty, zero, boundary

use iona::consensus::double_sign::{vote_guard_key, DoubleSignGuard};
use iona::consensus::messages::VoteType;
use iona::crypto::PublicKeyBytes;
use iona::types::Hash32;
use std::fs;
use tempfile::TempDir;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const TEST_HEIGHT: u64 = 10;
const TEST_ROUND: u32 = 0;
const TEST_OTHER_HEIGHT: u64 = 7;
const TEST_OTHER_ROUND: u32 = 1;

const BLOCK_HASH_A: u8 = 0xAA;
const BLOCK_HASH_B: u8 = 0xBB;
const BLOCK_HASH_C: u8 = 0xCC;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Create a `Hash32` filled with the same byte.
fn hash(byte: u8) -> Hash32 {
    Hash32([byte; 32])
}

/// Wrap a hash as `Some(_)` for vote APIs that accept nil votes.
fn opt_hash(byte: u8) -> Option<Hash32> {
    Some(hash(byte))
}

/// Borrow the temporary directory as a UTF-8 path.
fn temp_path(dir: &TempDir) -> &str {
    dir.path()
        .to_str()
        .expect("temporary directory path must be valid UTF-8")
}

/// Create a `DoubleSignGuard` for a validator whose public key is
/// 32 copies of `pk_byte`, rooted in the given temporary directory.
fn make_guard(dir: &TempDir, pk_byte: u8) -> DoubleSignGuard {
    let pk = PublicKeyBytes(vec![pk_byte; 32]);
    DoubleSignGuard::new(temp_path(dir), &pk)
        .expect("guard must load cleanly from a fresh temporary directory")
}

/// Assert that the guard **allowed** the operation.
///
/// The argument is evaluated exactly once.
macro_rules! assert_allowed {
    ($result:expr, $msg:expr) => {{
        let __result = $result;
        assert!(
            __result.is_ok(),
            "{} — expected OK, but guard denied with {:?}",
            $msg,
            __result.err(),
        );
    }};
}

/// Assert that the guard **denied** the operation.
///
/// The argument is evaluated exactly once.
macro_rules! assert_denied {
    ($result:expr, $msg:expr) => {{
        let __result = $result;
        assert!(
            __result.is_err(),
            "{} — expected DENIED, but guard allowed the operation",
            $msg,
        );
    }};
}

// ---------------------------------------------------------------------------
// A. Double-sign guard — equivocation prevention
// ---------------------------------------------------------------------------

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

    let result = g.check_vote(
        VoteType::Prevote,
        TEST_HEIGHT,
        TEST_ROUND,
        &opt_hash(BLOCK_HASH_B),
    );
    assert_denied!(result, "double prevote for different block at same position");
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
    assert_denied!(result, "nil vote after block vote at same position is equivocation");
}

#[test]
fn a_nil_vote_then_block_vote_same_position() {
    let dir = TempDir::new().unwrap();
    let g = make_guard(&dir, 5);

    g.record_vote(VoteType::Prevote, TEST_HEIGHT, TEST_ROUND, &None)
        .expect("nil vote accepted");

    let result = g.check_vote(
        VoteType::Prevote,
        TEST_HEIGHT,
        TEST_ROUND,
        &opt_hash(BLOCK_HASH_B),
    );
    assert_denied!(result, "block vote after nil vote at same position is equivocation");
}

// ---------------------------------------------------------------------------
// B. Replay protection — idempotent accepts
// ---------------------------------------------------------------------------

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

    let result = g.check_vote(
        VoteType::Precommit,
        TEST_HEIGHT,
        TEST_ROUND,
        &opt_hash(BLOCK_HASH_A),
    );
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

// ---------------------------------------------------------------------------
// C. Different positions are independent
// ---------------------------------------------------------------------------

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

    assert_allowed!(
        g.check_proposal(TEST_HEIGHT + 1, TEST_ROUND, &hash(BLOCK_HASH_A)),
        "same round at different height must be allowed"
    );
}

#[test]
fn c_nil_prevote_and_block_precommit_are_independent() {
    let dir = TempDir::new().unwrap();
    let g = make_guard(&dir, 11);

    g.record_vote(VoteType::Prevote, TEST_HEIGHT, TEST_ROUND, &None)
        .expect("nil prevote accepted");

    assert_allowed!(
        g.check_vote(
            VoteType::Precommit,
            TEST_HEIGHT,
            TEST_ROUND,
            &opt_hash(BLOCK_HASH_B),
        ),
        "precommit is independent of a nil prevote at the same position"
    );
}

// ---------------------------------------------------------------------------
// D. Guard survives restart (persistent storage)
// ---------------------------------------------------------------------------

#[test]
fn d_guard_rejects_double_sign_after_restart() {
    let dir = TempDir::new().unwrap();
    let path = temp_path(&dir);
    let pk = PublicKeyBytes(vec![20u8; 32]);

    {
        let g = DoubleSignGuard::new(path, &pk).expect("load guard");
        g.record_proposal(42, 0, &hash(0x42)).expect("record proposal");
    }

    {
        let g = DoubleSignGuard::new(path, &pk).expect("reload after restart");
        let result = g.check_proposal(42, 0, &hash(0xFF));
        assert_denied!(result, "double-sign must be prevented even after restart");
    }
}

#[test]
fn d_guard_allows_new_heights_after_restart() {
    let dir = TempDir::new().unwrap();
    let path = temp_path(&dir);
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
    let path = temp_path(&dir);
    let pk = PublicKeyBytes(vec![22u8; 32]);

    {
        let g = DoubleSignGuard::new(path, &pk).expect("guard instance");
        g.record_proposal(1, 0, &hash(1)).expect("record proposal");
        g.record_vote(VoteType::Prevote, 1, 0, &opt_hash(1))
            .expect("record prevote");
        g.record_vote(VoteType::Precommit, 1, 0, &opt_hash(1))
            .expect("record precommit");
    }

    {
        let g = DoubleSignGuard::new(path, &pk).expect("guard after restart");
        let (proposals, votes) = g.record_count();
        assert_eq!(proposals, 1, "must retain proposal count");
        assert_eq!(votes, 2, "must retain vote count");

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

#[test]
fn d_nil_vote_then_block_vote_rejected_after_restart() {
    let dir = TempDir::new().unwrap();
    let path = temp_path(&dir);
    let pk = PublicKeyBytes(vec![23u8; 32]);

    {
        let g = DoubleSignGuard::new(path, &pk).expect("guard instance");
        g.record_vote(VoteType::Prevote, 5, 0, &None)
            .expect("record nil prevote");
    }

    let g = DoubleSignGuard::new(path, &pk).expect("guard after restart");
    assert_denied!(
        g.check_vote(VoteType::Prevote, 5, 0, &opt_hash(1)),
        "block vote after nil vote must be rejected across restart"
    );
    assert_allowed!(
        g.check_vote(VoteType::Prevote, 5, 0, &None),
        "idempotent nil-vote replay must be allowed across restart"
    );
}

// ---------------------------------------------------------------------------
// E. Hash-chain integrity — tampered guard rejected
// ---------------------------------------------------------------------------

#[test]
fn e_tampered_guard_rejected_at_load() {
    let dir = TempDir::new().unwrap();
    let path = temp_path(&dir);
    let pk = PublicKeyBytes(vec![30u8; 32]);

    // Create a valid guard with one recorded proposal, then capture its
    // on-disk path via the public API.
    let guard_file = {
        let g = DoubleSignGuard::new(path, &pk).expect("initial guard");
        g.record_proposal(1, 0, &hash(1)).expect("record proposal");
        g.path().to_owned()
    };

    // Tamper: erase recorded proposals without updating the chain hash.
    let raw = fs::read_to_string(&guard_file).expect("read guard file");
    let mut json: serde_json::Value =
        serde_json::from_str(&raw).expect("parse guard file as JSON");
    json["proposals"] = serde_json::json!({});
    fs::write(
        &guard_file,
        serde_json::to_string(&json).expect("serialize tampered guard"),
    )
    .expect("write tampered guard file");

    let result = DoubleSignGuard::new(path, &pk);
    assert_denied!(result, "tampered guard file (hash mismatch) must be rejected at load");
}

#[test]
fn e_truncated_file_rejected() {
    let dir = TempDir::new().unwrap();
    let path = temp_path(&dir);
    let pk = PublicKeyBytes(vec![31u8; 32]);

    let guard_file = {
        let g = DoubleSignGuard::new(path, &pk).expect("initial guard");
        g.record_proposal(1, 0, &hash(1)).expect("record proposal");
        g.path().to_owned()
    };

    fs::write(&guard_file, "this is not json at all").expect("write garbage");

    let result = DoubleSignGuard::new(path, &pk);
    assert_denied!(result, "corrupt guard file must be rejected at load");
}

#[test]
fn e_missing_file_creates_fresh_guard() {
    let dir = TempDir::new().unwrap();
    let path = temp_path(&dir);
    let pk = PublicKeyBytes(vec![32u8; 32]);

    let g = DoubleSignGuard::new(path, &pk).expect("fresh guard must load");
    let (prop, vote) = g.record_count();
    assert_eq!(prop, 0, "fresh guard has zero proposals");
    assert_eq!(vote, 0, "fresh guard has zero votes");
}

#[test]
fn e_guard_files_are_isolated_per_public_key() {
    let dir = TempDir::new().unwrap();
    let path = temp_path(&dir);
    let pk_a = PublicKeyBytes(vec![33u8; 32]);
    let pk_b = PublicKeyBytes(vec![34u8; 32]);

    {
        let g = DoubleSignGuard::new(path, &pk_a).expect("guard A");
        g.record_proposal(1, 0, &hash(1)).expect("record A");
    }

    // A guard for a different validator must not observe A's state.
    let g_b = DoubleSignGuard::new(path, &pk_b).expect("guard B");
    let (prop, vote) = g_b.record_count();
    assert_eq!(prop, 0, "guard B must not inherit guard A's proposals");
    assert_eq!(vote, 0, "guard B must not inherit guard A's votes");
    assert_allowed!(
        g_b.check_proposal(1, 0, &hash(2)),
        "guard B must be independent from guard A"
    );
}

// ---------------------------------------------------------------------------
// F. Record-count tracking
// ---------------------------------------------------------------------------

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

    // Idempotent check must NOT increase the count.
    g.check_proposal(1, 0, &hash(1)).expect("idempotent check");
    let (prop2, _) = g.record_count();
    assert_eq!(prop2, 1, "idempotent check must not increase count");
}

// ---------------------------------------------------------------------------
// G. Guard path reporting
// ---------------------------------------------------------------------------

#[test]
fn g_guard_reports_path() {
    let dir = TempDir::new().unwrap();
    let pk = PublicKeyBytes(vec![50u8; 32]);
    let g = DoubleSignGuard::new(temp_path(&dir), &pk).expect("guard created");
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

#[test]
fn g_guard_path_is_stable_across_reloads() {
    let dir = TempDir::new().unwrap();
    let path = temp_path(&dir);
    let pk = PublicKeyBytes(vec![51u8; 32]);

    let p1 = {
        let g = DoubleSignGuard::new(path, &pk).expect("first load");
        g.path().to_owned()
    };
    let p2 = {
        let g = DoubleSignGuard::new(path, &pk).expect("second load");
        g.path().to_owned()
    };

    assert_eq!(p1, p2, "guard path must be deterministic across reloads");
}

// ---------------------------------------------------------------------------
// H. Edge cases
// ---------------------------------------------------------------------------

#[test]
fn h_check_before_record_always_allowed() {
    let dir = TempDir::new().unwrap();
    let g = make_guard(&dir, 60);

    assert_allowed!(
        g.check_proposal(TEST_HEIGHT, TEST_ROUND, &hash(BLOCK_HASH_A)),
        "check before any record must be allowed"
    );
    assert_allowed!(
        g.check_vote(
            VoteType::Prevote,
            TEST_HEIGHT,
            TEST_ROUND,
            &opt_hash(BLOCK_HASH_B)
        ),
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
