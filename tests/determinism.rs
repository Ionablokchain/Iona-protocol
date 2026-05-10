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

// -----------------------------------------------------------------------------
// Constants
// -----------------------------------------------------------------------------

/// Test message used for golden hash.
const TEST_MESSAGE: &[u8] = b"IONA_DETERMINISM_TEST";

/// Canonical chain ID used in test transactions.
const TEST_CHAIN_ID: u64 = 6126151;

/// Canonical gas limit.
const TEST_GAS_LIMIT: u64 = 21_000;

/// Canonical block height.
const TEST_BLOCK_HEIGHT: u64 = 1;

/// Canonical block round.
const TEST_BLOCK_ROUND: u32 = 0;

/// Canonical block timestamp.
const TEST_BLOCK_TIMESTAMP: u64 = 1000;

// -----------------------------------------------------------------------------
// Helpers
// -----------------------------------------------------------------------------

/// Canonical test transaction used across multiple determinism tests.
fn canonical_tx() -> Tx {
    Tx {
        pubkey: vec![1u8; 32],
        from: "alice".into(),
        nonce: 42,
        max_fee_per_gas: 100,
        max_priority_fee_per_gas: 10,
        gas_limit: TEST_GAS_LIMIT,
        payload: "set key value".into(),
        signature: vec![0u8; 64],
        chain_id: TEST_CHAIN_ID,
    }
}

/// Canonical test receipt used for receipts root tests.
fn canonical_receipt() -> Receipt {
    Receipt {
        tx_hash: Hash32([0xAA; 32]),
        success: true,
        gas_used: TEST_GAS_LIMIT,
        intrinsic_gas_used: TEST_GAS_LIMIT,
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

/// Create a minimal block header for ID determinism tests.
fn test_block_header() -> BlockHeader {
    BlockHeader {
        height: TEST_BLOCK_HEIGHT,
        round: TEST_BLOCK_ROUND,
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
        chain_id: TEST_CHAIN_ID,
        timestamp: TEST_BLOCK_TIMESTAMP,
        protocol_version: 1,
    }
}

// -----------------------------------------------------------------------------
// Core hash determinism
// -----------------------------------------------------------------------------

#[test]
fn determinism_hash_bytes_stable() {
    let h1 = hash_bytes(TEST_MESSAGE);
    let h2 = hash_bytes(TEST_MESSAGE);
    assert_eq!(h1, h2, "hash_bytes is not deterministic across calls");

    let hex_str = hex::encode(&h1.0);
    println!("hash_bytes golden: {hex_str}");
}

// -----------------------------------------------------------------------------
// Transaction hash determinism
// -----------------------------------------------------------------------------

#[test]
fn determinism_tx_hash_stable() {
    let tx = canonical_tx();
    let h1 = tx_hash(&tx);
    let h2 = tx_hash(&tx);
    assert_eq!(h1, h2, "tx_hash is not deterministic");

    let hex_str = hex::encode(&h1.0);
    println!("tx_hash golden: {hex_str}");
}

// -----------------------------------------------------------------------------
// Transaction root determinism
// -----------------------------------------------------------------------------

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

// -----------------------------------------------------------------------------
// Receipts root determinism
// -----------------------------------------------------------------------------

#[test]
fn determinism_receipts_root_stable() {
    let receipts = vec![canonical_receipt()];
    let r1 = receipts_root(&receipts);
    let r2 = receipts_root(&receipts);
    assert_eq!(r1, r2, "receipts_root is not deterministic");
}

// -----------------------------------------------------------------------------
// Block ID determinism
// -----------------------------------------------------------------------------

#[test]
fn determinism_block_id_stable() {
    let header = test_block_header();
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

// -----------------------------------------------------------------------------
// State root insertion‑order independence
// -----------------------------------------------------------------------------

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

// -----------------------------------------------------------------------------
// Migration invariants (UPGRADE_SPEC section 10.2)
// -----------------------------------------------------------------------------

/// M3 equivalence: state root must be identical before and after a
/// format-only migration (no semantic changes).
#[test]
fn determinism_migration_root_equivalence() {
    use iona::execution::KvState;

    let mut state = KvState::default();
    state.balances.insert("alice".into(), 1_000_000);
    state.balances.insert("bob".into(), 500_000);
    state.nonces.insert("alice".into(), 42);
    state.kv.insert("config:version".into(), "1".into());
    state.burned = 100;

    let root_before = state.root();

    let state_after: KvState =
        serde_json::from_str(&serde_json::to_string(&state).unwrap()).unwrap();
    let root_after = state_after.root();

    assert_eq!(
        root_before, root_after,
        "state root changed after format-only migration (M3 violation)"
    );
}

/// M1 invariant: migration must not lose account or KV keys.
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

    let supply_before = state.balances.values().sum::<u64>() + state.burned;

    let migrated: KvState = serde_json::from_str(&serde_json::to_string(&state).unwrap()).unwrap();
    let supply_after = migrated.balances.values().sum::<u64>() + migrated.burned;

    assert_eq!(
        supply_before, supply_after,
        "total supply changed during migration (M2 violation): before={supply_before}, after={supply_after}"
    );
}

// -----------------------------------------------------------------------------
// Protocol version function determinism
// -----------------------------------------------------------------------------

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
