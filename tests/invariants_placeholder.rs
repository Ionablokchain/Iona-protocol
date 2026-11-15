//! Consensus and state invariant tests.
//!
//! # Invariants verified here
//!
//! * **Conservation** — sum of all balances + burned == initial supply,
//!   before and after arbitrary state transitions.
//! * **Nonce monotonicity** — mempool drains transactions strictly in
//!   ascending nonce order per sender, and never returns a transaction
//!   whose nonce is below the last confirmed nonce for its sender.
//! * **RBF policy** — duplicate nonces are rejected unless the new tip
//!   exceeds the old tip by at least the mempool's replace threshold.
//! * **Mempool bounds** — global capacity is enforced; a full mempool
//!   rejects rather than silently drops.
//! * **Merkle root determinism** — two states with identical contents
//!   have the same root regardless of construction order.
//! * **Merkle root sensitivity** — any field that contributes to state
//!   (balances, nonces, KV, VM storage, burned) changes the root when
//!   changed.
//! * **Stake power accounting** — `total_power` counts only Active
//!   validators; jailed and tombstoned validators contribute zero.
//!
//! # Out of scope
//!
//! * Double-commit detection at the same `(height, round)`. That is
//!   enforced by [`iona::consensus::double_sign`] and covered in
//!   `tests/consensus_adversarial.rs`, not here.
//! * Execution-layer fee/gas arithmetic. That is covered in
//!   `tests/integration.rs` and `tests/golden_vectors.rs`.
//!
//! The tests in this file exercise the **invariants** themselves, using
//! manual state manipulation where it makes the invariant clearer. They
//! deliberately do not duplicate the execution-layer tests.

use iona::crypto::PublicKeyBytes;
use iona::execution::KvState;
use iona::mempool::Mempool;
use iona::slashing::{StakeLedger, ValidatorRecord, ValidatorStatus};
use iona::types::{Hash32, Tx};

// ---------------------------------------------------------------------------
// Test configuration
// ---------------------------------------------------------------------------

const TEST_CHAIN_ID: u64 = 6_126_151;
const DEFAULT_GAS_LIMIT: u64 = 100_000;
const DEFAULT_MAX_FEE: u64 = 10;
const DEFAULT_TIP: u64 = 5;
const DEFAULT_PAYLOAD: &str = "set x 1";

/// Initial supply used across balance-conservation tests.
const INITIAL_SUPPLY: u64 = 1_000_000;

/// Amount moved between accounts in the conservation tests.
const TRANSFER_AMOUNT: u64 = 100;

/// Fee burned per simulated transaction. Manual value — the execution
/// layer's real fee computation is tested elsewhere.
const GAS_FEE: u64 = 21_000;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn make_tx(from: &str, nonce: u64, max_fee: u64, tip: u64, payload: &str) -> Tx {
    assert!(max_fee >= tip, "max_fee must be >= tip");
    Tx {
        pubkey: vec![0u8; 32],
        from: from.to_string(),
        nonce,
        max_fee_per_gas: max_fee,
        max_priority_fee_per_gas: tip,
        gas_limit: DEFAULT_GAS_LIMIT,
        payload: payload.to_string(),
        signature: vec![0u8; 64],
        chain_id: TEST_CHAIN_ID,
    }
}

fn make_default_tx(from: &str, nonce: u64) -> Tx {
    make_tx(from, nonce, DEFAULT_MAX_FEE, DEFAULT_TIP, DEFAULT_PAYLOAD)
}

/// Assert an invariant with a message that names the property.
macro_rules! assert_invariant {
    ($cond:expr, $($msg:tt)+) => {
        assert!($cond, "INVARIANT VIOLATED: {}", format!($($msg)+));
    };
}

/// Sum of all balances plus burned. The quantity that must be conserved.
fn total_supply(state: &KvState) -> u64 {
    state
        .balances
        .values()
        .try_fold(state.burned, |acc, &b| acc.checked_add(b))
        .expect("supply overflow")
}

// ===========================================================================
// Balance conservation
// ===========================================================================

#[test]
fn invariant_balance_conservation_single_transfer() {
    let mut state = KvState::default();
    state.balances.insert("alice".into(), 600_000);
    state.balances.insert("bob".into(), 400_000);

    assert_eq!(
        total_supply(&state),
        INITIAL_SUPPLY,
        "initial balances must sum to initial supply",
    );

    // Alice pays amount + fee; Bob receives amount; fee is burned.
    let fee = TRANSFER_AMOUNT + GAS_FEE;
    let alice = *state.balances.get("alice").expect("alice present");
    assert!(alice >= fee, "alice cannot afford this transfer");
    *state.balances.get_mut("alice").unwrap() = alice - fee;

    *state.balances.entry("bob".into()).or_insert(0) += TRANSFER_AMOUNT;
    state.burned = state.burned.saturating_add(GAS_FEE);

    assert_invariant!(
        total_supply(&state) == INITIAL_SUPPLY,
        "balances + burned must equal initial supply after transfer \
         (got {}, expected {})",
        total_supply(&state),
        INITIAL_SUPPLY,
    );
}

#[test]
fn invariant_balance_conservation_multiple_transfers() {
    let mut state = KvState::default();
    state.balances.insert("alice".into(), 800_000);
    state.balances.insert("bob".into(), 200_000);

    let initial = total_supply(&state);

    // Transfer 1: alice → bob.
    let alice = *state.balances.get("alice").unwrap();
    *state.balances.get_mut("alice").unwrap() = alice - (TRANSFER_AMOUNT + GAS_FEE);
    *state.balances.entry("bob".into()).or_insert(0) += TRANSFER_AMOUNT;
    state.burned = state.burned.saturating_add(GAS_FEE);

    assert_invariant!(
        total_supply(&state) == initial,
        "supply changed after first transfer",
    );

    // Transfer 2: bob → alice.
    let half = TRANSFER_AMOUNT / 2;
    let bob = *state.balances.get("bob").unwrap();
    assert!(bob >= half + GAS_FEE, "bob cannot afford this transfer");
    *state.balances.get_mut("bob").unwrap() = bob - (half + GAS_FEE);
    *state.balances.entry("alice".into()).or_insert(0) += half;
    state.burned = state.burned.saturating_add(GAS_FEE);

    assert_invariant!(
        total_supply(&state) == initial,
        "supply changed after second transfer",
    );
}

// ===========================================================================
// Mempool nonce ordering
// ===========================================================================

#[test]
fn invariant_mempool_drains_in_nonce_order() {
    let mut pool = Mempool::new(1000);

    for nonce in [0, 1, 2] {
        pool.push(make_default_tx("alice", nonce))
            .expect("push must succeed with free capacity");
    }

    let drained = pool.drain_best(10);
    let nonces: Vec<u64> = drained.iter().map(|t| t.nonce).collect();

    assert_eq!(nonces.len(), 3, "must drain all three transactions");
    for w in nonces.windows(2) {
        assert_invariant!(
            w[0] < w[1],
            "nonces out of order: {} >= {}",
            w[0],
            w[1],
        );
    }
}

#[test]
fn invariant_mempool_drains_in_nonce_order_per_sender() {
    let mut pool = Mempool::new(1000);

    // Interleave alice and bob submissions.
    for (sender, nonce) in [
        ("alice", 1u64), ("bob", 0u64), ("alice", 0u64),
        ("bob", 2u64),   ("alice", 2u64), ("bob", 1u64),
    ] {
        pool.push(make_default_tx(sender, nonce))
            .expect("push must succeed with free capacity");
    }

    let drained = pool.drain_best(10);

    for sender in ["alice", "bob"] {
        let nonces: Vec<u64> = drained
            .iter()
            .filter(|t| t.from == sender)
            .map(|t| t.nonce)
            .collect();

        assert_eq!(
            nonces.len(), 3,
            "{sender}: expected 3 transactions",
        );
        for w in nonces.windows(2) {
            assert_invariant!(
                w[0] < w[1],
                "{sender} nonces out of order: {} >= {}",
                w[0],
                w[1],
            );
        }
    }
}

#[test]
fn invariant_mempool_rejects_duplicate_nonce_without_bump() {
    let mut pool = Mempool::new(1000);
    pool.push(make_tx("alice", 0, 100, 50, "first"))
        .expect("first push must succeed");

    // Same tip — not a valid replacement.
    assert_invariant!(
        pool.push(make_tx("alice", 0, 100, 50, "same tip")).is_err(),
        "duplicate nonce with identical tip must be rejected",
    );

    // Lower tip — not a valid replacement.
    assert_invariant!(
        pool.push(make_tx("alice", 0, 100, 40, "lower tip")).is_err(),
        "duplicate nonce with lower tip must be rejected",
    );
}

#[test]
fn invariant_mempool_accepts_clear_rbf_bump() {
    // Use a 2× bump so the test does not depend on the exact threshold
    // used by the mempool. Threshold precision is covered in
    // `tests/integration.rs::test_mempool_rbf`.
    let mut pool = Mempool::new(1000);
    pool.push(make_tx("alice", 0, 100, 50, "first"))
        .expect("first push must succeed");

    pool.push(make_tx("alice", 0, 100, 100, "replace"))
        .expect("2x tip bump must be accepted as a replacement");
    assert_eq!(
        pool.metrics.rbf_replaced, 1,
        "RBF counter must increment on a valid replacement",
    );
}

#[test]
fn invariant_mempool_never_returns_below_confirmed_nonce() {
    let mut pool = Mempool::new(1000);
    for nonce in [0, 1, 2] {
        pool.push(make_default_tx("alice", nonce))
            .expect("push must succeed with free capacity");
    }

    // Simulate confirming nonces 0 and 1 for alice.
    pool.remove_confirmed("alice", 2);

    let remaining = pool.drain_best(10);
    for tx in &remaining {
        if tx.from == "alice" {
            assert_invariant!(
                tx.nonce >= 2,
                "confirmed tx returned by mempool: nonce={}",
                tx.nonce,
            );
        }
    }
}

#[test]
fn invariant_mempool_enforces_capacity() {
    const CAP: usize = 5;
    let mut pool = Mempool::new(CAP);
    let mut rejected = 0usize;

    for i in 0..(CAP * 2) as u64 {
        let sender = format!("user{i}");
        if pool.push(make_default_tx(&sender, 0)).is_err() {
            rejected += 1;
        }
    }

    assert_eq!(
        pool.len(), CAP,
        "pool must be exactly at capacity",
    );
    assert_invariant!(
        rejected > 0,
        "a full mempool must reject surplus transactions (rejected {})",
        rejected,
    );
}

#[test]
#[should_panic(expected = "capacity must be > 0")]
fn invariant_mempool_rejects_zero_capacity() {
    let _pool = Mempool::new(0);
}

// ===========================================================================
// Merkle root determinism
// ===========================================================================

#[test]
fn invariant_state_root_is_content_addressed() {
    // Two states with identical content built in different orders must
    // produce the same root. This is the property the previous version
    // of this test was supposed to verify but did not: cloning a
    // `BTreeMap` and re-inserting the same key is a no-op.
    let mut s1 = KvState::default();
    s1.balances.insert("alice".into(), 100);
    s1.balances.insert("bob".into(), 200);
    s1.nonces.insert("alice".into(), 3);
    s1.kv.insert("mykey".into(), "myval".into());
    s1.burned = 42;

    let mut s2 = KvState::default();
    // Different insertion order, same final content.
    s2.burned = 42;
    s2.kv.insert("mykey".into(), "myval".into());
    s2.nonces.insert("alice".into(), 3);
    s2.balances.insert("bob".into(), 200);
    s2.balances.insert("alice".into(), 100);

    assert_eq!(
        s1.root(), s2.root(),
        "state root must depend on content, not insertion order",
    );
}

// ===========================================================================
// Merkle root sensitivity
// ===========================================================================

#[test]
fn invariant_state_root_sensitive_to_balance() {
    let mut a = KvState::default();
    a.balances.insert("alice".into(), 100);

    let mut b = KvState::default();
    b.balances.insert("alice".into(), 101);

    assert_ne!(
        a.root(), b.root(),
        "balance delta must change the state root",
    );
}

#[test]
fn invariant_state_root_sensitive_to_nonce() {
    let mut a = KvState::default();
    a.nonces.insert("alice".into(), 1);

    let mut b = KvState::default();
    b.nonces.insert("alice".into(), 2);

    assert_ne!(
        a.root(), b.root(),
        "nonce delta must change the state root",
    );
}

#[test]
fn invariant_state_root_sensitive_to_kv() {
    let mut a = KvState::default();
    a.kv.insert("k".into(), "v1".into());

    let mut b = KvState::default();
    b.kv.insert("k".into(), "v2".into());

    assert_ne!(
        a.root(), b.root(),
        "KV value delta must change the state root",
    );
}

#[test]
fn invariant_state_root_sensitive_to_burned() {
    let mut a = KvState::default();
    a.burned = 0;

    let mut b = KvState::default();
    b.burned = 1;

    assert_ne!(
        a.root(), b.root(),
        "burned delta must change the state root",
    );
}

#[test]
fn invariant_state_root_sensitive_to_vm_storage() {
    let mut a = KvState::default();
    a.vm.storage.insert(([0xAA; 32], [0x01; 32]), [0xFF; 32]);

    let b = KvState::default();

    assert_ne!(
        a.root(), b.root(),
        "VM storage addition must change the state root",
    );
}

// ===========================================================================
// Stake ledger accounting
// ===========================================================================

fn pk(byte: u8) -> PublicKeyBytes {
    PublicKeyBytes(vec![byte; 32])
}

#[test]
fn invariant_stake_ledger_total_power_counts_only_active() {
    let mut ledger = StakeLedger::default();
    let pk1 = pk(1);
    let pk2 = pk(2);

    ledger.validators.insert(pk1.clone(), ValidatorRecord::new(1000));
    ledger.validators.insert(pk2.clone(), ValidatorRecord::new(500));

    assert_eq!(
        ledger.total_power(), 1500,
        "both validators active: total_power must be 1500",
    );

    // Jail pk2 — contributes zero to total_power.
    ledger.validators.get_mut(&pk2).unwrap().status = ValidatorStatus::Jailed {
        since_height: 100,
        slash_count: 1,
    };
    assert_eq!(
        ledger.total_power(), 1000,
        "jailed validator must not contribute to total_power",
    );

    // Tombstone pk1 — contributes zero.
    ledger.validators.get_mut(&pk1).unwrap().status = ValidatorStatus::Tombstoned;
    assert_eq!(
        ledger.total_power(), 0,
        "tombstoned validator must not contribute to total_power",
    );
}

#[test]
fn invariant_stake_ledger_unknown_validator_has_zero_power() {
    let ledger = StakeLedger::default();
    assert_eq!(
        ledger.power_of(&pk(0xFF)), 0,
        "unknown validator must have zero power",
    );
}

// ===========================================================================
// Cross-cutting invariants
// ===========================================================================

#[test]
fn invariant_supply_conserved_across_snapshot_roundtrip() {
    // A serialize/deserialize round-trip is a no-op on content, so
    // total supply must be identical before and after. Complements the
    // format-stability checks in `tests/golden_vectors.rs` with a
    // semantic invariant.
    let mut state = KvState::default();
    state.balances.insert("alice".into(), 300);
    state.balances.insert("bob".into(), 200);
    state.balances.insert("carol".into(), 100);
    state.burned = 50;

    let before = total_supply(&state);

    let json = serde_json::to_string(&state).expect("serialize");
    let after_state: KvState = serde_json::from_str(&json).expect("deserialize");
    let after = total_supply(&after_state);

    assert_eq!(
        before, after,
        "total supply must be preserved across snapshot round-trip",
    );
    assert_eq!(
        state.root(), after_state.root(),
        "state root must be preserved across snapshot round-trip",
    );
}

// Silence the unused-import lint for Hash32 (used only via type inference
// through KvState). If `Hash32` is genuinely unused after edits, remove it.
#[allow(dead_code)]
const _: fn() -> Option<Hash32> = || None;
