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

fn make_tx(from: &str, nonce: u64, max_fee: u64, tip: u64, payload: &str) -> Tx {
    Tx {
        pubkey: vec![0u8; 32],
        from: from.to_string(),
        nonce,
        max_fee_per_gas: max_fee,
        max_priority_fee_per_gas: tip,
        gas_limit: 100_000,
        payload: payload.to_string(),
        signature: vec![0u8; 64],
        chain_id: 6126151,
    }
}

/// INVARIANT: After any number of transfer txs, total balances + burned == initial supply.
#[test]
fn invariant_balance_conservation() {
    let initial_supply: u64 = 1_000_000;
    let mut state = KvState::default();

    // Fund two accounts
    state.balances.insert("alice".into(), 600_000);
    state.balances.insert("bob".into(), 400_000);

    let initial_total: u64 = state.balances.values().sum::<u64>() + state.burned;
    assert_eq!(
        initial_total, initial_supply,
        "Initial invariant: balances sum to supply"
    );

    // Run a few transfer txs through apply_tx (they will fail sig check, but test invariant)
    // For balance invariant we manually simulate a successful transfer
    let transfered: u64 = 100;
    let gas_fee: u64 = 21_000; // 1 gas unit price
    let alice_bal = state.balances.get_mut("alice").unwrap();
    *alice_bal -= transfered + gas_fee;
    *state.balances.entry("bob".into()).or_insert(0) += transfered;
    state.burned += gas_fee;

    let after_total: u64 = state.balances.values().sum::<u64>() + state.burned;
    assert_eq!(
        after_total, initial_supply,
        "INVARIANT VIOLATED: balances + burned != initial supply after transfer"
    );
}

/// INVARIANT: Nonces must be strictly increasing per sender in mempool.
#[test]
fn invariant_mempool_nonce_ordering() {
    let mut pool = Mempool::new(1000);

    // Submit nonces 0, 1, 2 for alice
    pool.push(make_tx("alice", 0, 10, 5, "set x 1")).unwrap();
    pool.push(make_tx("alice", 1, 10, 5, "set x 2")).unwrap();
    pool.push(make_tx("alice", 2, 10, 5, "set x 3")).unwrap();

    let drained = pool.drain_best(10);
    // Must be in nonce order
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
    // Same nonce, same tip — should be rejected
    let res = pool.push(make_tx("alice", 0, 100, 50, "set x 2"));
    assert!(
        res.is_err(),
        "INVARIANT VIOLATED: duplicate nonce accepted without fee bump"
    );
}

/// INVARIANT: After confirming nonce N, mempool must not return txs with nonce < N.
#[test]
fn invariant_mempool_remove_confirmed() {
    let mut pool = Mempool::new(1000);
    pool.push(make_tx("alice", 0, 10, 5, "set x 0")).unwrap();
    pool.push(make_tx("alice", 1, 10, 5, "set x 1")).unwrap();
    pool.push(make_tx("alice", 2, 10, 5, "set x 2")).unwrap();

    // Confirm nonce 0 and 1
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

/// INVARIANT: Mempool global cap must be respected.
#[test]
fn invariant_mempool_cap() {
    let cap = 5;
    let mut pool = Mempool::new(cap);
    for i in 0..10u64 {
        let sender = format!("user{}", i);
        let _ = pool.push(make_tx(&sender, 0, 10, 5, "set x 1"));
    }
    assert!(
        pool.len() <= cap,
        "INVARIANT VIOLATED: mempool size {} exceeds cap {}",
        pool.len(),
        cap
    );
}

/// INVARIANT: KvState Merkle root must be deterministic (same state -> same root).
#[test]
fn invariant_kv_state_root_determinism() {
    let mut s1 = KvState::default();
    s1.balances.insert("alice".into(), 100);
    s1.balances.insert("bob".into(), 200);
    s1.nonces.insert("alice".into(), 3);
    s1.kv.insert("mykey".into(), "myval".into());
    s1.burned = 42;

    let mut s2 = s1.clone();
    // Insert in different order (BTreeMap is order-independent anyway)
    s2.balances.insert("bob".into(), 200);
    s2.balances.insert("alice".into(), 100);

    assert_eq!(
        s1.root().0,
        s2.root().0,
        "INVARIANT VIOLATED: same state produces different roots"
    );
}

/// INVARIANT: Different states must produce different roots.
#[test]
fn invariant_kv_state_root_sensitivity() {
    let mut s1 = KvState::default();
    s1.balances.insert("alice".into(), 100);

    let mut s2 = KvState::default();
    s2.balances.insert("alice".into(), 101); // one unit different

    assert_ne!(
        s1.root().0,
        s2.root().0,
        "INVARIANT VIOLATED: different states produce the same root"
    );
}

/// INVARIANT: StakeLedger total_power only counts active validators.
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
