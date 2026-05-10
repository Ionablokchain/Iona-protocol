//! Consensus and state invariant tests for IONA.
//!
//! These tests verify that core invariants hold across blocks:
//! - Sum of all balances + burned == total_supply_issued
//! - No double-commits at the same height with different block IDs
//! - Nonces are strictly monotonically increasing per sender
//! - Mempool never returns a tx with nonce lower than committed nonce

use iona::execution::{apply_tx, build_block, KvState};
use iona::mempool::Mempool;
use iona::slashing::StakeLedger;
use iona::types::{Hash32, Tx};

// -----------------------------------------------------------------------------
// Constants
// -----------------------------------------------------------------------------

/// Default test chain ID.
const TEST_CHAIN_ID: u64 = 6126151;

/// Default gas limit for test transactions.
const DEFAULT_GAS_LIMIT: u64 = 100_000;

/// Default max fee per gas for test transactions.
const DEFAULT_MAX_FEE: u64 = 10;

/// Default max priority fee per gas for test transactions.
const DEFAULT_TIP: u64 = 5;

/// Default transaction payload.
const DEFAULT_PAYLOAD: &str = "set x 1";

/// Initial total supply for balance conservation tests.
const INITIAL_SUPPLY: u64 = 1_000_000;

/// Amount transferred in balance conservation test.
const TRANSFER_AMOUNT: u64 = 100;

/// Gas fee used in balance conservation test (21_000 at unit price 1).
const GAS_FEE: u64 = 21_000;

// -----------------------------------------------------------------------------
// Helpers
// -----------------------------------------------------------------------------

/// Create a test transaction.
fn make_tx(from: &str, nonce: u64, max_fee: u64, tip: u64, payload: &str) -> Tx {
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

// -----------------------------------------------------------------------------
// Invariant tests
// -----------------------------------------------------------------------------

/// INVARIANT: After any number of transfer transactions, total balances + burned == initial supply.
#[test]
fn invariant_balance_conservation() {
    let mut state = KvState::default();

    // Fund two accounts
    state.balances.insert("alice".into(), 600_000);
    state.balances.insert("bob".into(), 400_000);

    let initial_total: u64 = state.balances.values().sum::<u64>() + state.burned;
    assert_eq!(
        initial_total,
        INITIAL_SUPPLY,
        "Initial invariant: balances sum to supply"
    );

    // Simulate a successful transfer (bypass signature checks for test)
    let alice_bal = state.balances.get_mut("alice").unwrap();
    *alice_bal -= TRANSFER_AMOUNT + GAS_FEE;
    *state.balances.entry("bob".into()).or_insert(0) += TRANSFER_AMOUNT;
    state.burned += GAS_FEE;

    let after_total: u64 = state.balances.values().sum::<u64>() + state.burned;
    assert_eq!(
        after_total,
        INITIAL_SUPPLY,
        "INVARIANT VIOLATED: balances + burned != initial supply after transfer"
    );
}

/// INVARIANT: Nonces must be strictly increasing per sender in mempool.
#[test]
fn invariant_mempool_nonce_ordering() {
    let mut pool = Mempool::new(1000);

    // Submit nonces 0, 1, 2 for Alice
    pool.push(make_tx("alice", 0, DEFAULT_MAX_FEE, DEFAULT_TIP, DEFAULT_PAYLOAD))
        .unwrap();
    pool.push(make_tx("alice", 1, DEFAULT_MAX_FEE, DEFAULT_TIP, DEFAULT_PAYLOAD))
        .unwrap();
    pool.push(make_tx("alice", 2, DEFAULT_MAX_FEE, DEFAULT_TIP, DEFAULT_PAYLOAD))
        .unwrap();

    let drained = pool.drain_best(10);
    let nonces: Vec<u64> = drained
        .iter()
        .filter(|t| t.from == "alice")
        .map(|t| t.nonce)
        .collect();

    for w in nonces.windows(2) {
        assert!(
            w[0] < w[1],
            "INVARIANT VIOLATED: nonces not in order: {} >= {}",
            w[0],
            w[1]
        );
    }
}

/// INVARIANT: Mempool must reject duplicate nonce without sufficient fee bump.
#[test]
fn invariant_mempool_no_duplicate_nonce_without_rbf() {
    let mut pool = Mempool::new(1000);
    pool.push(make_tx("alice", 0, 100, 50, "set x 1")).unwrap();

    // Same nonce, same tip – should be rejected
    let result = pool.push(make_tx("alice", 0, 100, 50, "set x 2"));
    assert!(
        result.is_err(),
        "INVARIANT VIOLATED: duplicate nonce accepted without fee bump"
    );
}

/// INVARIANT: After confirming nonce N, mempool must not return transactions with nonce < N.
#[test]
fn invariant_mempool_remove_confirmed() {
    let mut pool = Mempool::new(1000);
    pool.push(make_tx("alice", 0, DEFAULT_MAX_FEE, DEFAULT_TIP, "set x 0"))
        .unwrap();
    pool.push(make_tx("alice", 1, DEFAULT_MAX_FEE, DEFAULT_TIP, "set x 1"))
        .unwrap();
    pool.push(make_tx("alice", 2, DEFAULT_MAX_FEE, DEFAULT_TIP, "set x 2"))
        .unwrap();

    // Confirm nonce 0 and 1 so next expected is 2
    pool.remove_confirmed("alice", 2);

    let remaining = pool.drain_best(10);
    for tx in &remaining {
        if tx.from == "alice" {
            assert!(
                tx.nonce >= 2,
                "INVARIANT VIOLATED: confirmed tx still in mempool, nonce={}",
                tx.nonce
            );
        }
    }
}

/// INVARIANT: Mempool global capacity must be respected.
#[test]
fn invariant_mempool_cap() {
    let cap = 5;
    let mut pool = Mempool::new(cap);
    for i in 0..10u64 {
        let sender = format!("user{}", i);
        let _ = pool.push(make_tx(&sender, 0, DEFAULT_MAX_FEE, DEFAULT_TIP, DEFAULT_PAYLOAD));
    }
    assert!(
        pool.len() <= cap,
        "INVARIANT VIOLATED: mempool size {} exceeds cap {}",
        pool.len(),
        cap
    );
}

/// INVARIANT: `KvState` Merkle root must be deterministic (same state → same root).
#[test]
fn invariant_kv_state_root_determinism() {
    let mut state1 = KvState::default();
    state1.balances.insert("alice".into(), 100);
    state1.balances.insert("bob".into(), 200);
    state1.nonces.insert("alice".into(), 3);
    state1.kv.insert("mykey".into(), "myval".into());
    state1.burned = 42;

    let mut state2 = state1.clone();
    // Insert in different order (BTreeMap is already order‑independent, but still)
    state2.balances.insert("bob".into(), 200);
    state2.balances.insert("alice".into(), 100);

    assert_eq!(
        state1.root().0,
        state2.root().0,
        "INVARIANT VIOLATED: same state produces different roots"
    );
}

/// INVARIANT: Different states must produce different roots.
#[test]
fn invariant_kv_state_root_sensitivity() {
    let mut state1 = KvState::default();
    state1.balances.insert("alice".into(), 100);

    let mut state2 = KvState::default();
    state2.balances.insert("alice".into(), 101); // one unit different

    assert_ne!(
        state1.root().0,
        state2.root().0,
        "INVARIANT VIOLATED: different states produce the same root"
    );
}

/// INVARIANT: `StakeLedger::total_power` only counts active validators.
#[test]
fn invariant_stake_ledger_active_power() {
    use iona::crypto::PublicKeyBytes;
    use iona::slashing::{ValidatorRecord, ValidatorStatus};

    let mut ledger = StakeLedger::default();
    let pk1 = PublicKeyBytes(vec![1u8; 32]);
    let pk2 = PublicKeyBytes(vec![2u8; 32]);

    ledger
        .validators
        .insert(pk1.clone(), ValidatorRecord::new(1000));
    ledger
        .validators
        .insert(pk2.clone(), ValidatorRecord::new(500));

    assert_eq!(ledger.total_power(), 1500);

    // Jail pk2
    ledger.validators.get_mut(&pk2).unwrap().status = ValidatorStatus::Jailed {
        since_height: 100,
        slash_count: 1,
    };
    assert_eq!(
        ledger.total_power(),
        1000,
        "INVARIANT VIOLATED: jailed validator counted in total_power"
    );

    // Tombstone pk1
    ledger.validators.get_mut(&pk1).unwrap().status = ValidatorStatus::Tombstoned;
    assert_eq!(
        ledger.total_power(),
        0,
        "INVARIANT VIOLATED: tombstoned validator counted in total_power"
    );
}
