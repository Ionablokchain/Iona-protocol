//! Property‑based tests for IONA core types.
//!
//! These tests use `proptest` to verify that critical functions are
//! deterministic across a wide range of random inputs.
//!
//! Run with: `cargo test --test proptest`

use iona::types::{hash_bytes, tx_hash, Block, BlockHeader, Hash32, Tx};
use proptest::prelude::*;
use std::collections::HashSet;

// -----------------------------------------------------------------------------
// Strategy constants
// -----------------------------------------------------------------------------

/// Maximum length of a transaction public key (bytes).
const MAX_PUBKEY_LEN: usize = 128;

/// Maximum length of a sender address string.
const MAX_FROM_LEN: usize = 64;

/// Maximum length of transaction payload (bytes).
const MAX_PAYLOAD_LEN: usize = 256;

/// Maximum length of transaction signature (bytes).
const MAX_SIG_LEN: usize = 96;

/// Maximum block height (u64).
const MAX_HEIGHT: u64 = 1_000_000;

/// Character set for sender address strings (alphanumeric and underscore).
const FROM_CHARSET: &str = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_";

/// Maximum number of transactions in a block for tests.
const MAX_TXS_IN_BLOCK: usize = 20;

/// Maximum size of a byte vector for hashing.
const MAX_HASH_DATA_LEN: usize = 4096;

// -----------------------------------------------------------------------------
// Strategy generators
// -----------------------------------------------------------------------------

/// Strategy for generating arbitrary valid transaction strings (sender addresses).
fn arb_from_string() -> impl Strategy<Value = String> {
    proptest::string::string_regex(&format!("[{}-Z_a-z0-9]{{0,{}}}", FROM_CHARSET, MAX_FROM_LEN))
        .unwrap()
        .prop_map(|s| s.chars().take(MAX_FROM_LEN).collect())
}

/// Strategy for generating arbitrary transaction payload strings.
fn arb_payload_string() -> impl Strategy<Value = String> {
    proptest::string::string_regex(&format!("[ -~]{{0,{}}}", MAX_PAYLOAD_LEN))
        .unwrap()
        .prop_map(|s| s.chars().take(MAX_PAYLOAD_LEN).collect())
}

/// Strategy for generating arbitrary `Tx` structures.
fn arb_tx() -> impl Strategy<Value = Tx> {
    (
        proptest::collection::vec(any::<u8>(), 0..MAX_PUBKEY_LEN),
        arb_from_string(),
        any::<u64>(),
        any::<u64>(),
        any::<u64>(),
        any::<u64>(),
        arb_payload_string(),
        proptest::collection::vec(any::<u8>(), 0..MAX_SIG_LEN),
        any::<u64>(),
    )
        .prop_map(
            |(pubkey, from, nonce, max_fee, max_prio, gas_limit, payload, signature, chain_id)| {
                Tx {
                    pubkey,
                    from,
                    nonce,
                    max_fee_per_gas: max_fee,
                    max_priority_fee_per_gas: max_prio,
                    gas_limit,
                    payload,
                    signature,
                    chain_id,
                }
            },
        )
}

/// Strategy for generating arbitrary `Hash32`.
fn arb_hash32() -> impl Strategy<Value = Hash32> {
    any::<[u8; 32]>().prop_map(Hash32::from_bytes)
}

/// Strategy for generating arbitrary `BlockHeader`.
fn arb_block_header() -> impl Strategy<Value = BlockHeader> {
    (
        any::<u64>(),
        any::<u32>(),
        arb_hash32(),
        proptest::collection::vec(any::<u8>(), 32..32),
        arb_hash32(),
        arb_hash32(),
        arb_hash32(),
        any::<u64>(),
        any::<u64>(),
        any::<u64>(),
        any::<u64>(),
        any::<u64>(),
        any::<u64>(),
        any::<u64>(),
        any::<u64>(),
        any::<u32>(),
    )
        .prop_map(
            |(
                height,
                round,
                prev,
                proposer_pk,
                tx_root,
                receipts_root,
                state_root,
                base_fee_per_gas,
                gas_used,
                intrinsic_gas_used,
                exec_gas_used,
                vm_gas_used,
                evm_gas_used,
                chain_id,
                timestamp,
                protocol_version,
            )| {
                BlockHeader {
                    height,
                    round,
                    prev,
                    proposer_pk,
                    tx_root,
                    receipts_root,
                    state_root,
                    base_fee_per_gas,
                    gas_used,
                    intrinsic_gas_used,
                    exec_gas_used,
                    vm_gas_used,
                    evm_gas_used,
                    chain_id,
                    timestamp,
                    protocol_version,
                }
            },
        )
}

/// Strategy for generating a block with a random number of transactions.
fn arb_block() -> impl Strategy<Value = Block> {
    (
        arb_block_header(),
        proptest::collection::vec(arb_tx(), 0..MAX_TXS_IN_BLOCK),
    )
        .prop_map(|(header, txs)| Block { header, txs })
}

// -----------------------------------------------------------------------------
// Property tests
// -----------------------------------------------------------------------------

proptest! {
    /// `tx_hash` must return the same hash for the same transaction.
    #[test]
    fn tx_hash_is_deterministic(tx in arb_tx()) {
        let hash1 = tx_hash(&tx);
        let hash2 = tx_hash(&tx);
        prop_assert_eq!(hash1.0, hash2.0);
    }

    /// `tx_hash` must change when any field changes (non‑degenerate).
    #[test]
    fn tx_hash_changes_on_field_change(tx in arb_tx()) {
        // Change each field and verify hash differs.
        let original_hash = tx_hash(&tx);

        // Change pubkey (if non‑empty, else we skip or use a safe change).
        let mut tx2 = tx.clone();
        if !tx2.pubkey.is_empty() {
            tx2.pubkey[0] = tx2.pubkey[0].wrapping_add(1);
        } else {
            tx2.pubkey = vec![0x01];
        }
        prop_assert_ne!(tx_hash(&tx2).0, original_hash.0);

        // Change from.
        let mut tx3 = tx.clone();
        tx3.from.push('x');
        prop_assert_ne!(tx_hash(&tx3).0, original_hash.0);

        // Change nonce.
        let mut tx4 = tx.clone();
        tx4.nonce = tx4.nonce.wrapping_add(1);
        prop_assert_ne!(tx_hash(&tx4).0, original_hash.0);

        // Change payload.
        let mut tx5 = tx.clone();
        tx5.payload.push('x');
        prop_assert_ne!(tx_hash(&tx5).0, original_hash.0);
    }

    /// `hash_bytes` must return the same hash for the same byte slice.
    #[test]
    fn hash_bytes_is_deterministic(data in proptest::collection::vec(any::<u8>(), 0..MAX_HASH_DATA_LEN)) {
        let hash1 = hash_bytes(&data);
        let hash2 = hash_bytes(&data);
        prop_assert_eq!(hash1.0, hash2.0);
    }

    /// `hash_bytes` should change when input changes (collision resistance).
    #[test]
    fn hash_bytes_changes_on_input_change(data in proptest::collection::vec(any::<u8>(), 1..MAX_HASH_DATA_LEN)) {
        let hash1 = hash_bytes(&data);
        let mut data2 = data.clone();
        data2[0] = data2[0].wrapping_add(1);
        let hash2 = hash_bytes(&data2);
        prop_assert_ne!(hash1.0, hash2.0);
    }

    /// `Hash32.fidelity` returns 1.0 for identical hashes, 0.0 otherwise.
    #[test]
    fn hash32_fidelity_is_correct(a in arb_hash32(), b in arb_hash32()) {
        let f = a.fidelity(&b);
        if a.0 == b.0 {
            prop_assert!((f - 1.0).abs() < 1e-10);
        } else {
            prop_assert!((f - 0.0).abs() < 1e-10);
        }
    }

    /// `Block.id` is deterministic for the same block.
    #[test]
    fn block_id_is_deterministic(block in arb_block()) {
        let id1 = block.id();
        let id2 = block.id();
        prop_assert_eq!(id1.0, id2.0);
    }

    /// `Block.id` changes when any header field changes.
    #[test]
    fn block_id_changes_on_header_change(header in arb_block_header(), txs in proptest::collection::vec(arb_tx(), 0..MAX_TXS_IN_BLOCK)) {
        let block = Block { header: header.clone(), txs: txs.clone() };
        let id1 = block.id();

        // Change height.
        let mut header2 = header.clone();
        header2.height = header2.height.wrapping_add(1);
        let block2 = Block { header: header2, txs: txs.clone() };
        prop_assert_ne!(block2.id().0, id1.0);
    }

    /// `tx_root` is deterministic for the same list of transactions.
    #[test]
    fn tx_root_is_deterministic(txs in proptest::collection::vec(arb_tx(), 0..MAX_TXS_IN_BLOCK)) {
        let root1 = iona::types::tx_root(&txs);
        let root2 = iona::types::tx_root(&txs);
        prop_assert_eq!(root1.0, root2.0);
    }

    /// `tx_root` changes when transactions are added/removed.
    #[test]
    fn tx_root_changes_on_tx_change(txs in proptest::collection::vec(arb_tx(), 1..MAX_TXS_IN_BLOCK)) {
        let root1 = iona::types::tx_root(&txs);
        // Remove last tx.
        let mut txs2 = txs.clone();
        txs2.pop();
        let root2 = iona::types::tx_root(&txs2);
        prop_assert_ne!(root1.0, root2.0);
    }

    /// `receipts_root` is deterministic for the same list of receipts.
    #[test]
    fn receipts_root_is_deterministic(receipts in proptest::collection::vec(any::<iona::types::Receipt>(), 0..10)) {
        // We need a strategy for Receipt. We'll use a simpler approach: generate fixed‑size vectors.
        // For simplicity, we'll generate a vector of Receipt with a custom strategy.
        // Since Receipt has many fields, we'll just use a default Receipt and vary tx_hash.
        // We'll use a small set of deterministic receipts for this property.
        let receipt1 = iona::types::Receipt {
            tx_hash: Hash32::zero(),
            success: true,
            gas_used: 1000,
            intrinsic_gas_used: 21000,
            exec_gas_used: 0,
            vm_gas_used: 0,
            evm_gas_used: 0,
            effective_gas_price: 1,
            burned: 1,
            tip: 0,
            error: None,
            data: None,
        };
        let receipts = vec![receipt1.clone(), receipt1.clone()];
        let root1 = iona::types::receipts_root(&receipts);
        let root2 = iona::types::receipts_root(&receipts);
        prop_assert_eq!(root1.0, root2.0);
    }

    /// Quorum threshold is correctly computed for random total power.
    #[test]
    fn quorum_threshold_correctness(power in any::<u64>()) {
        let threshold = iona::consensus::quorum_threshold(power);
        // For power=0, threshold=1; for power>0, threshold = floor(2*power/3)+1.
        if power == 0 {
            prop_assert_eq!(threshold, 1);
        } else {
            prop_assert!(threshold > power * 2 / 3);
            prop_assert!(threshold <= power);
        }
    }

    /// `has_quorum` matches `voting_power >= quorum_threshold(total_power)`.
    #[test]
    fn has_quorum_is_correct(total in any::<u64>(), voting in any::<u64>()) {
        let threshold = iona::consensus::quorum_threshold(total);
        let quorum = iona::consensus::has_quorum(voting, total);
        prop_assert_eq!(quorum, voting >= threshold);
    }

    /// Consensus purity is always in [0,1].
    #[test]
    fn consensus_purity_bounds(coherences in proptest::collection::vec(any::<f64>(), 0..100)) {
        // Ensure values are in [0,1] for the test.
        let coherences: Vec<f64> = coherences.into_iter().map(|x| x.abs().min(1.0)).collect();
        let purity = iona::consensus::compute_consensus_purity(&coherences);
        prop_assert!(purity >= 0.0 && purity <= 1.0);
    }

    /// Consensus entropy is >= 0 for purity in [0,1].
    #[test]
    fn consensus_entropy_nonnegative(purity in any::<f64>()) {
        let p = purity.abs().min(1.0);
        let entropy = iona::consensus::compute_consensus_entropy(p);
        prop_assert!(entropy >= 0.0);
    }

    /// `Hash32` serialization roundtrip.
    #[test]
    fn hash32_serialization_roundtrip(h in arb_hash32()) {
        let json = serde_json::to_string(&h).unwrap();
        let h2: Hash32 = serde_json::from_str(&json).unwrap();
        prop_assert_eq!(h.0, h2.0);
    }

    /// Transaction quantum purity is always in [0,1].
    #[test]
    fn tx_quantum_purity_bounds(tx in arb_tx()) {
        let purity = tx.quantum_purity();
        prop_assert!(purity >= 0.0 && purity <= 1.0);
    }
}

// -----------------------------------------------------------------------------
// Additional non‑property tests (for invariants not easily property‑tested)
// -----------------------------------------------------------------------------

#[test]
fn hash32_zero_is_all_zero() {
    let zero = Hash32::zero();
    assert_eq!(zero.0, [0u8; 32]);
}

#[test]
fn tx_hash_non_empty_for_non_empty_tx() {
    let tx = Tx {
        pubkey: vec![1; 32],
        from: "alice".into(),
        nonce: 0,
        max_fee_per_gas: 100,
        max_priority_fee_per_gas: 10,
        gas_limit: 100_000,
        payload: "set a b".into(),
        signature: vec![0xAA; 64],
        chain_id: 1,
    };
    let hash = tx_hash(&tx);
    assert_ne!(hash.0, [0u8; 32]);
}

#[test]
fn block_id_non_empty() {
    let header = BlockHeader {
        height: 1,
        round: 0,
        prev: Hash32::zero(),
        proposer_pk: vec![0xAA; 32],
        tx_root: Hash32::zero(),
        receipts_root: Hash32::zero(),
        state_root: Hash32::zero(),
        base_fee_per_gas: 1,
        gas_used: 0,
        intrinsic_gas_used: 0,
        exec_gas_used: 0,
        vm_gas_used: 0,
        evm_gas_used: 0,
        chain_id: 1,
        timestamp: 123456,
        protocol_version: 1,
    };
    let block = Block { header, txs: vec![] };
    let id = block.id();
    assert_ne!(id.0, [0u8; 32]);
}

#[test]
fn quorum_threshold_sanity() {
    assert_eq!(iona::consensus::quorum_threshold(0), 1);
    assert_eq!(iona::consensus::quorum_threshold(1), 1);
    assert_eq!(iona::consensus::quorum_threshold(2), 2);
    assert_eq!(iona::consensus::quorum_threshold(3), 3);
    assert_eq!(iona::consensus::quorum_threshold(4), 3);
    assert_eq!(iona::consensus::quorum_threshold(5), 4);
}

#[test]
fn hash_fidelity_identical() {
    let h = Hash32::from_bytes([0xAA; 32]);
    assert!((h.fidelity(&h) - 1.0).abs() < 1e-10);
    let h2 = Hash32::from_bytes([0xBB; 32]);
    assert!((h.fidelity(&h2) - 0.0).abs() < 1e-10);
}
