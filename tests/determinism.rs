//! Golden-vector determinism tests.
//!
//! Consensus-critical functions MUST produce byte-identical output across
//! builds, platforms, and Rust versions. If any golden vector changes,
//! every node on the network will compute a different state root, block
//! ID, or transaction hash — which manifests as a hard fork.
//!
//! # How golden tests work
//!
//! Every `GOLDEN_*` constant pins the exact hex output of one function.
//! A test failure means either:
//!
//! * the change is a regression → revert it, or
//! * the change is intentional (planned protocol upgrade) → update the
//!   constant and ship it as a hard-fork release.
//!
//! # Filling in goldens on first run
//!
//! All `GOLDEN_*` constants ship empty. On the first `cargo test` run, each
//! golden test panics with the actual value printed in the message. Copy
//! each value into its constant, re-run, and the file is green.
//!
//! # Scope
//!
//! Hashing is a pure function of its input bytes. This file pins the
//! *outputs* and asserts a handful of algebraic properties (order
//! independence, order sensitivity, migration invariants). It does not
//! model "quantum coherence" — determinism is not a physical quantity.

use iona::execution::KvState;
use iona::protocol::version::{version_for_height, ProtocolActivation};
use iona::types::{
    hash_bytes, receipts_root, tx_hash, tx_root, Block, BlockHeader, Hash32, Receipt, Tx,
};

// ---------------------------------------------------------------------------
// Golden vectors
// ---------------------------------------------------------------------------
//
// Pin the exact hex output of every consensus-critical function. Leave the
// string empty on first checkout; a test run will print the value.

/// `hex::encode(hash_bytes(b"IONA_DETERMINISM_TEST").0)`
const GOLDEN_HASH_BYTES: &str = "";

/// `hex::encode(tx_hash(&canonical_tx()).0)`
const GOLDEN_TX_HASH: &str = "";

/// `hex::encode(tx_root(&[]).0)`
const GOLDEN_TX_ROOT_EMPTY: &str = "";

/// `hex::encode(tx_root(&[canonical_tx(), canonical_tx_with_nonce(43)]).0)`
const GOLDEN_TX_ROOT_TWO: &str = "";

/// `hex::encode(receipts_root(&[]).0)`
const GOLDEN_RECEIPTS_ROOT_EMPTY: &str = "";

/// `hex::encode(receipts_root(&[canonical_receipt()]).0)`
const GOLDEN_RECEIPTS_ROOT_ONE: &str = "";

/// `hex::encode(Block { header: test_block_header(), txs: vec![] }.id().0)`
const GOLDEN_BLOCK_ID_EMPTY: &str = "";

/// `hex::encode(KvState { kv: { a=1, b=2, c=3 } }.root().0)`
const GOLDEN_STATE_ROOT_KV: &str = "";

/// `hex::encode(KvState { balances: { alice=1000, bob=2000 } }.root().0)`
const GOLDEN_STATE_ROOT_BALANCES: &str = "";

// ---------------------------------------------------------------------------
// Test vectors
// ---------------------------------------------------------------------------

/// Canonical input to the hashing primitives.
const TEST_MESSAGE: &[u8] = b"IONA_DETERMINISM_TEST";

/// Canonical chain ID used in test transactions.
const TEST_CHAIN_ID: u64 = 6_126_151;

/// Canonical gas limit.
const TEST_GAS_LIMIT: u64 = 21_000;

/// Canonical block height / round / timestamp for synthetic headers.
const TEST_BLOCK_HEIGHT: u64 = 1;
const TEST_BLOCK_ROUND: u32 = 0;
const TEST_BLOCK_TIMESTAMP: u64 = 1000;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Assert that `actual` matches the pinned golden vector `expected`.
///
/// If `expected` is empty, panics with the actual value so the developer
/// can copy it into the corresponding `GOLDEN_*` constant on first run.
fn assert_golden(actual: &str, expected: &str, name: &str) {
    if expected.is_empty() {
        panic!(
            "\n\n[golden] `{name}` is not pinned yet.\n\
             Copy the value below into the matching `GOLDEN_*` constant:\n\n\
             \t\"{actual}\"\n"
        );
    }
    assert_eq!(
        actual, expected,
        "\n\n[golden] MISMATCH for `{name}`\n\
         expected: {expected}\n\
         actual:   {actual}\n\n\
         If the change is intentional (protocol upgrade), update the constant\n\
         and ship as a hard-fork release. Otherwise, revert.\n"
    );
}

/// Assert equality with determinism-specific context.
///
/// This is a plain function, not a macro, so both sides are evaluated
/// exactly once.
fn assert_deterministic_eq<T, M>(left: T, right: T, msg: M)
where
    T: PartialEq + std::fmt::Debug,
    M: std::fmt::Display,
{
    assert_eq!(left, right, "DETERMINISM VIOLATION: {msg}");
}

/// Canonical test transaction.
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

/// Second canonical transaction, differing only in `nonce`.
fn canonical_tx_with_nonce(nonce: u64) -> Tx {
    let mut tx = canonical_tx();
    tx.nonce = nonce;
    tx
}

/// Canonical test receipt.
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

/// Synthetic block header whose roots are derived from the canonical
/// empty inputs, so it is internally consistent.
fn test_block_header() -> BlockHeader {
    BlockHeader {
        height: TEST_BLOCK_HEIGHT,
        round: TEST_BLOCK_ROUND,
        prev: Hash32::zero(),
        proposer_pk: vec![0u8; 32],
        tx_root: tx_root(&[]),
        receipts_root: receipts_root(&[]),
        state_root: KvState::default().root(),
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

// ===========================================================================
// Golden vectors — pinned hash outputs
// ===========================================================================

#[test]
fn golden_hash_bytes() {
    let h1 = hash_bytes(TEST_MESSAGE);
    let h2 = hash_bytes(TEST_MESSAGE);
    assert_deterministic_eq(h1, h2, "hash_bytes is not deterministic across calls");
    assert_golden(
        &hex::encode(&h1.0),
        GOLDEN_HASH_BYTES,
        "hash_bytes(IONA_DETERMINISM_TEST)",
    );
}

#[test]
fn golden_tx_hash() {
    let tx = canonical_tx();
    let h1 = tx_hash(&tx);
    let h2 = tx_hash(&tx);
    assert_deterministic_eq(h1, h2, "tx_hash is not deterministic across calls");
    assert_golden(
        &hex::encode(&h1.0),
        GOLDEN_TX_HASH,
        "tx_hash(canonical_tx)",
    );
}

#[test]
fn golden_tx_root_empty() {
    let r1 = tx_root(&[]);
    let r2 = tx_root(&[]);
    assert_deterministic_eq(r1, r2, "tx_root([]) is not deterministic");
    assert_golden(
        &hex::encode(&r1.0),
        GOLDEN_TX_ROOT_EMPTY,
        "tx_root(empty)",
    );
}

#[test]
fn golden_tx_root_with_two_txs() {
    let txs = vec![canonical_tx(), canonical_tx_with_nonce(43)];
    let r1 = tx_root(&txs);
    let r2 = tx_root(&txs);
    assert_deterministic_eq(r1, r2, "tx_root(2 txs) is not deterministic");
    assert_golden(
        &hex::encode(&r1.0),
        GOLDEN_TX_ROOT_TWO,
        "tx_root([nonce=42, nonce=43])",
    );
}

#[test]
fn golden_receipts_root_empty() {
    let r1 = receipts_root(&[]);
    let r2 = receipts_root(&[]);
    assert_deterministic_eq(r1, r2, "receipts_root([]) is not deterministic");
    assert_golden(
        &hex::encode(&r1.0),
        GOLDEN_RECEIPTS_ROOT_EMPTY,
        "receipts_root(empty)",
    );
}

#[test]
fn golden_receipts_root_one() {
    let receipts = vec![canonical_receipt()];
    let r1 = receipts_root(&receipts);
    let r2 = receipts_root(&receipts);
    assert_deterministic_eq(r1, r2, "receipts_root(1 receipt) is not deterministic");
    assert_golden(
        &hex::encode(&r1.0),
        GOLDEN_RECEIPTS_ROOT_ONE,
        "receipts_root([canonical_receipt])",
    );
}

#[test]
fn golden_block_id_empty() {
    let block = Block {
        header: test_block_header(),
        txs: vec![],
    };
    let id1 = block.id();
    let id2 = block.id();
    assert_deterministic_eq(id1, id2, "block.id() is not deterministic");
    assert_golden(
        &hex::encode(&id1.0),
        GOLDEN_BLOCK_ID_EMPTY,
        "block_id(empty block)",
    );
}

#[test]
fn golden_state_root_kv() {
    let mut s = KvState::default();
    s.kv.insert("a".into(), "1".into());
    s.kv.insert("b".into(), "2".into());
    s.kv.insert("c".into(), "3".into());
    let root = s.root();
    assert_golden(
        &hex::encode(&root.0),
        GOLDEN_STATE_ROOT_KV,
        "state_root(kv: a=1, b=2, c=3)",
    );
}

#[test]
fn golden_state_root_balances() {
    let mut s = KvState::default();
    s.balances.insert("alice".into(), 1000);
    s.balances.insert("bob".into(), 2000);
    let root = s.root();
    assert_golden(
        &hex::encode(&root.0),
        GOLDEN_STATE_ROOT_BALANCES,
        "state_root(balances: alice=1000, bob=2000)",
    );
}

// ===========================================================================
// Determinism properties
// ===========================================================================

#[test]
fn determinism_tx_hash_nonce_sensitive() {
    let h1 = tx_hash(&canonical_tx());
    let h2 = tx_hash(&canonical_tx_with_nonce(43));
    assert_ne!(
        h1, h2,
        "different nonces must produce different transaction hashes"
    );
}

#[test]
fn determinism_tx_root_order_sensitive() {
    // Merkle roots are order-sensitive by design: (tx_a, tx_b) != (tx_b, tx_a).
    let tx_a = canonical_tx();
    let tx_b = canonical_tx_with_nonce(43);

    let root_ab = tx_root(&[tx_a.clone(), tx_b.clone()]);
    let root_ba = tx_root(&[tx_b, tx_a]);

    assert_ne!(
        root_ab, root_ba,
        "tx_root must be order-sensitive (Merkle property)"
    );
}

#[test]
fn determinism_block_id_txs_sensitive() {
    // Two blocks must differ when their txs differ. Build the header with
    // matching `tx_root` so the test does not rely on `Block::id()`
    // implementation details.
    let tx = canonical_tx();

    let mut header_with_tx = test_block_header();
    header_with_tx.tx_root = tx_root(&[tx.clone()]);
    let block_with_tx = Block {
        header: header_with_tx,
        txs: vec![tx],
    };

    let block_without_tx = Block {
        header: test_block_header(),
        txs: vec![],
    };

    assert_ne!(
        block_with_tx.id(),
        block_without_tx.id(),
        "blocks with different transactions must have different IDs"
    );
}

#[test]
fn determinism_state_root_kv_order_independent() {
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
        "state root must not depend on kv insertion order"
    );
}

#[test]
fn determinism_state_root_balances_order_independent() {
    let mut s1 = KvState::default();
    s1.balances.insert("alice".into(), 1000);
    s1.balances.insert("bob".into(), 2000);

    let mut s2 = KvState::default();
    s2.balances.insert("bob".into(), 2000);
    s2.balances.insert("alice".into(), 1000);

    assert_eq!(
        s1.root(),
        s2.root(),
        "state root must not depend on balance insertion order"
    );
}

// ===========================================================================
// Migration invariants (UPGRADE_SPEC section 10.2)
// ===========================================================================

/// M3: a format-only migration (serialize → deserialize) must preserve the
/// state root exactly.
#[test]
fn migration_preserves_state_root() {
    let mut state = KvState::default();
    state.balances.insert("alice".into(), 1_000_000);
    state.balances.insert("bob".into(), 500_000);
    state.nonces.insert("alice".into(), 42);
    state.kv.insert("config:version".into(), "1".into());
    state.burned = 100;

    let root_before = state.root();
    let roundtrip: KvState =
        serde_json::from_str(&serde_json::to_string(&state).expect("serialize"))
            .expect("deserialize");
    let root_after = roundtrip.root();

    assert_deterministic_eq(
        root_before,
        root_after,
        "state root changed after format-only migration (M3 violation)",
    );
}

/// M1: a migration must not lose account or KV keys.
///
/// `HashMap` iteration order is non-deterministic, so both sides are sorted
/// before comparison.
#[test]
fn migration_preserves_keys() {
    let mut state = KvState::default();
    state.balances.insert("alice".into(), 1000);
    state.balances.insert("bob".into(), 2000);
    state.balances.insert("charlie".into(), 3000);
    state.kv.insert("x".into(), "1".into());
    state.kv.insert("y".into(), "2".into());

    let mut balances_before: Vec<String> = state.balances.keys().cloned().collect();
    let mut kv_before: Vec<String> = state.kv.keys().cloned().collect();
    balances_before.sort();
    kv_before.sort();

    let migrated: KvState =
        serde_json::from_str(&serde_json::to_string(&state).expect("serialize"))
            .expect("deserialize");

    let mut balances_after: Vec<String> = migrated.balances.keys().cloned().collect();
    let mut kv_after: Vec<String> = migrated.kv.keys().cloned().collect();
    balances_after.sort();
    kv_after.sort();

    assert_deterministic_eq(
        balances_before,
        balances_after,
        "account keys lost during migration (M1 violation)",
    );
    assert_deterministic_eq(
        kv_before,
        kv_after,
        "KV keys lost during migration (M1 violation)",
    );
}

/// M2: total supply must be conserved across a migration.
#[test]
fn migration_preserves_supply() {
    let mut state = KvState::default();
    state.balances.insert("alice".into(), 1_000_000);
    state.balances.insert("bob".into(), 500_000);
    state.burned = 50_000;

    let supply_before = state.balances.values().sum::<u64>() + state.burned;

    let migrated: KvState =
        serde_json::from_str(&serde_json::to_string(&state).expect("serialize"))
            .expect("deserialize");
    let supply_after = migrated.balances.values().sum::<u64>() + migrated.burned;

    assert_deterministic_eq(
        supply_before,
        supply_after,
        format!(
            "total supply changed during migration (M2 violation): \
             before={supply_before}, after={supply_after}"
        ),
    );
}

/// M4: VM storage and nonces must survive a round-trip serialization.
#[test]
fn migration_preserves_vm_storage() {
    let mut state = KvState::default();
    let contract = [0xAAu8; 32];
    let key = [0xBBu8; 32];
    let value = [0xCCu8; 32];
    state.vm.storage.insert((contract, key), value);
    state.vm.nonces.insert(contract, 5);

    let storage_before = state.vm.storage.clone();
    let nonces_before = state.vm.nonces.clone();

    let migrated: KvState =
        serde_json::from_str(&serde_json::to_string(&state).expect("serialize"))
            .expect("deserialize");

    assert_deterministic_eq(
        storage_before,
        migrated.vm.storage,
        "VM storage lost during migration (M4 violation)",
    );
    assert_deterministic_eq(
        nonces_before,
        migrated.vm.nonces,
        "VM nonces lost during migration (M4 violation)",
    );
}

// ===========================================================================
// Protocol version determinism
// ===========================================================================

fn pv_test_activations() -> Vec<ProtocolActivation> {
    vec![
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
    ]
}

#[test]
fn determinism_pv_function_stable() {
    let activations = pv_test_activations();

    for height in [0, 1, 50, 99, 100, 105, 110, 200] {
        let pv1 = version_for_height(height, &activations);
        let pv2 = version_for_height(height, &activations);
        assert_deterministic_eq(
            pv1,
            pv2,
            format!("PV mapping not deterministic at height {height}"),
        );

        let expected = if height < 100 { 1 } else { 2 };
        assert_eq!(
            pv1, expected,
            "wrong PV at height {height}: expected {expected}, got {pv1}"
        );
    }
}

#[test]
fn determinism_pv_grace_period_boundary() {
    let activations = pv_test_activations();

    assert_eq!(version_for_height(99, &activations), 1, "pre-activation");
    assert_eq!(version_for_height(100, &activations), 2, "activation height");
    assert_eq!(version_for_height(110, &activations), 2, "grace period ends");
}
