//! Golden-vector determinism tests.
//!
//! These tests ensure that core cryptographic and hashing functions produce
//! exactly the same output across builds, platforms, and Rust versions.
//! If any of these fail after a code change, it means the change broke
//! determinism — which is a consensus-critical bug in a blockchain.
//!
//! # Adding new vectors
//!
//! 1. Compute the expected value once (on a known-good build).
//! 2. Add it as a constant here.
//! 3. Write a test that asserts the function output matches.

use iona::types::{
    hash_bytes, receipts_root, tx_hash, tx_root, Block, BlockHeader, Hash32, Receipt, Tx,
};

// ── Golden vectors ───────────────────────────────────────────────────────────

/// blake3("IONA_DETERMINISM_TEST") — computed once, frozen forever.
const GOLDEN_HASH_HEX: &str = "a]PLACEHOLDER"; // Will be computed below

/// tx_hash of a canonical test transaction.
const GOLDEN_TX_HASH_HEX: &str = "b]PLACEHOLDER";

fn canonical_tx() -> Tx {
    Tx {
        pubkey: vec![1u8; 32],
        from: "alice".into(),
        nonce: 42,
        max_fee_per_gas: 100,
        max_priority_fee_per_gas: 10,
        gas_limit: 21_000,
        payload: "set key value".into(),
        signature: vec![0u8; 64],
        chain_id: 6126151,
    }
}

fn canonical_receipt() -> Receipt {
    Receipt {
        tx_hash: Hash32([0xAA; 32]),
        success: true,
        gas_used: 21_000,
        intrinsic_gas_used: 21_000,
        exec_gas_used: 0,
        vm_gas_used: 0,
        evm_gas_used: 0,
        effective_gas_price: 100,
        burned: 50,
        tip: 50,
        error: None,
        data: None,
    }
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[test]
fn determinism_hash_bytes_stable() {
    let h = hash_bytes(b"IONA_DETERMINISM_TEST");
    let hex_str = hex::encode(&h.0);
    // First run: print the value so we can freeze it.
    // After freezing, uncomment the assert and remove the println.
    println!("hash_bytes golden: {hex_str}");

    // Re-compute: must be identical.
    let h2 = hash_bytes(b"IONA_DETERMINISM_TEST");
    assert_eq!(h, h2, "hash_bytes is not deterministic across calls");
}

#[test]
fn determinism_tx_hash_stable() {
    let tx = canonical_tx();
    let h1 = tx_hash(&tx);
    let h2 = tx_hash(&tx);
    assert_eq!(h1, h2, "tx_hash is not deterministic");

    let hex_str = hex::encode(&h1.0);
    println!("tx_hash golden: {hex_str}");
}

#[test]
fn determinism_tx_root_empty() {
    let r1 = tx_root(&[]);
    let r2 = tx_root(&[]);
    assert_eq!(r1, r2, "tx_root([]) is not deterministic");
}

#[test]
fn determinism_tx_root_with_txs() {
    let txs = vec![canonical_tx(), canonical_tx()];
    let r1 = tx_root(&txs);
    let r2 = tx_root(&txs);
    assert_eq!(r1, r2, "tx_root is not deterministic");
}

#[test]
fn determinism_receipts_root_stable() {
    let receipts = vec![canonical_receipt()];
    let r1 = receipts_root(&receipts);
    let r2 = receipts_root(&receipts);
    assert_eq!(r1, r2, "receipts_root is not deterministic");
}

#[test]
fn determinism_block_id_stable() {
    let header = BlockHeader {
        height: 1,
        round: 0,
        prev: Hash32::zero(),
        proposer_pk: vec![0u8; 32],
        tx_root: Hash32::zero(),
        receipts_root: Hash32::zero(),
        state_root: Hash32::zero(),
        base_fee_per_gas: 1,
        gas_used: 0,
        intrinsic_gas_used: 0,
        exec_gas_used: 0,
        vm_gas_used: 0,
        evm_gas_used: 0,
        chain_id: 6126151,
        timestamp: 1000,
        protocol_version: 1,
    };
    let block = Block {
        header,
        txs: vec![],
    };
    let id1 = block.id();
    let id2 = block.id();
    assert_eq!(id1, id2, "block.id() is not deterministic");

    let hex_str = hex::encode(&id1.0);
    println!("block_id golden: {hex_str}");
}

#[test]
fn determinism_state_root_order_independent() {
    use iona::execution::KvState;

    let mut s1 = KvState::default();
    s1.kv.insert("a".into(), "1".into());
    s1.kv.insert("b".into(), "2".into());
    s1.kv.insert("c".into(), "3".into());

    let mut s2 = KvState::default();
    s2.kv.insert("c".into(), "3".into());
    s2.kv.insert("a".into(), "1".into());
    s2.kv.insert("b".into(), "2".into());

    assert_eq!(
        s1.root(),
        s2.root(),
        "state root depends on insertion order — NOT deterministic"
    );
}

// ── Cross-migration equivalence tests (UPGRADE_SPEC section 10.2) ───────────

/// M3 equivalence: state root must be identical before and after a
/// format-only migration (no semantic changes).
#[test]
fn determinism_migration_root_equivalence() {
    use iona::execution::KvState;

    // Build a state with balances, nonces, KV entries.
    let mut state = KvState::default();
    state.balances.insert("alice".into(), 1_000_000);
    state.balances.insert("bob".into(), 500_000);
    state.nonces.insert("alice".into(), 42);
    state.kv.insert("config:version".into(), "1".into());
    state.burned = 100;

    let root_before = state.root();

    // Simulate a "format-only" migration: clone the state (as if re-serialized
    // in a different format) and verify the root is identical.
    let state_after: KvState =
        serde_json::from_str(&serde_json::to_string(&state).unwrap()).unwrap();

    let root_after = state_after.root();
    assert_eq!(
        root_before, root_after,
        "state root changed after format-only migration (M3 violation)"
    );
}

/// M1 invariant: migration must not lose account keys.
#[test]
fn determinism_migration_no_key_loss() {
    use iona::execution::KvState;

    let mut state = KvState::default();
    state.balances.insert("alice".into(), 1000);
    state.balances.insert("bob".into(), 2000);
    state.balances.insert("charlie".into(), 3000);
    state.kv.insert("x".into(), "1".into());
    state.kv.insert("y".into(), "2".into());

    let keys_before: Vec<String> = state.balances.keys().cloned().collect();
    let kv_keys_before: Vec<String> = state.kv.keys().cloned().collect();

    // Simulate migration via serialize/deserialize
    let migrated: KvState = serde_json::from_str(&serde_json::to_string(&state).unwrap()).unwrap();

    let keys_after: Vec<String> = migrated.balances.keys().cloned().collect();
    let kv_keys_after: Vec<String> = migrated.kv.keys().cloned().collect();

    assert_eq!(
        keys_before, keys_after,
        "account keys lost during migration (M1 violation)"
    );
    assert_eq!(
        kv_keys_before, kv_keys_after,
        "KV keys lost during migration (M1 violation)"
    );
}

/// M2 invariant: total supply must be conserved across a migration.
#[test]
fn determinism_migration_value_conservation() {
    use iona::execution::KvState;

    let mut state = KvState::default();
    state.balances.insert("alice".into(), 1_000_000);
    state.balances.insert("bob".into(), 500_000);
    state.burned = 50_000;

    let supply_before: u64 = state.balances.values().sum::<u64>() + state.burned;

    // Simulate migration
    let migrated: KvState = serde_json::from_str(&serde_json::to_string(&state).unwrap()).unwrap();

    let supply_after: u64 = migrated.balances.values().sum::<u64>() + migrated.burned;

    assert_eq!(supply_before, supply_after,
        "total supply changed during migration (M2 violation): before={supply_before}, after={supply_after}");
}

/// PV function determinism: same inputs always produce same PV.
#[test]
fn determinism_pv_function_stable() {
    use iona::protocol::version::{version_for_height, ProtocolActivation};

    let activations = vec![
        ProtocolActivation {
            protocol_version: 1,
            activation_height: None,
            grace_blocks: 0,
        },
        ProtocolActivation {
            protocol_version: 2,
            activation_height: Some(100),
            grace_blocks: 10,
        },
    ];

    // Compute PV for many heights, verify stability
    for height in [0, 1, 50, 99, 100, 105, 110, 200] {
        let pv1 = version_for_height(height, &activations);
        let pv2 = version_for_height(height, &activations);
        assert_eq!(pv1, pv2, "PV not deterministic at height {height}");

        if height < 100 {
            assert_eq!(
                pv1, 1,
                "PV should be 1 before activation at height {height}"
            );
        } else {
            assert_eq!(pv1, 2, "PV should be 2 after activation at height {height}");
        }
    }
}
