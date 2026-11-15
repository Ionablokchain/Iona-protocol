//! Property-based tests for IONA core types.
//!
//! Verifies determinism, sensitivity, and algebraic properties of the
//! consensus-critical primitives: transaction hashing, block hashing,
//! transaction and receipt Merkle roots, and quorum threshold.
//!
//! # What is verified
//!
//! * **Determinism** — hashing the same input twice yields the same
//!   output.
//! * **Sensitivity** — changing any single field of the input changes
//!   the output. This is stronger than determinism: without it, a
//!   Byzantine validator could substitute one transaction for another
//!   while preserving the hash.
//! * **Quorum threshold** — `quorum_threshold` and `has_quorum` agree,
//!   and the threshold satisfies the Byzantine bound `2n/3 < t <= n`
//!   (with `t = 1` for `n = 0`).
//! * **Serialization round-trip** — `Hash32` survives JSON round-trip.
//!
//! # What is **not** verified here
//!
//! * Golden byte vectors. Those live in `tests/golden_vectors.rs` and
//!   pin exact hex output. Property tests verify relationships between
//!   hashes, not their specific values.
//! * Collision resistance in any formal sense. That is a cryptographic
//!   assumption, not something a property test can prove.
//!
//! Run with: `cargo test --test proptest`

use iona::types::{
    hash_bytes, receipts_root, tx_hash, tx_root, Block, BlockHeader, Hash32, Receipt, Tx,
};
use proptest::prelude::*;

// ---------------------------------------------------------------------------
// Strategy limits
// ---------------------------------------------------------------------------

const MAX_PUBKEY_LEN: usize = 128;
const MAX_FROM_LEN: usize = 64;
const MAX_PAYLOAD_LEN: usize = 256;
const MAX_SIG_LEN: usize = 96;
const MAX_TXS_IN_BLOCK: usize = 20;
const MAX_HASH_DATA_LEN: usize = 4096;
const MAX_RECEIPTS: usize = 10;

/// Every `BlockHeader` from the consensus engine carries a 32-byte
/// proposer public key. Using the exact length (rather than a range)
/// matches how headers are built in production.
const PROPOSER_PK_LEN: usize = 32;

// ---------------------------------------------------------------------------
// Strategies
// ---------------------------------------------------------------------------

/// Sender addresses: US-ASCII alphanumerics plus underscore, up to
/// `MAX_FROM_LEN` characters.
fn arb_from_string() -> impl Strategy<Value = String> {
    // `{{` and `}}` are the format-string escapes for literal braces.
    proptest::string::string_regex(&format!("[A-Za-z0-9_]{{0,{MAX_FROM_LEN}}}"))
        .expect("from-string regex must compile")
}

/// Payloads: printable ASCII, up to `MAX_PAYLOAD_LEN` characters.
fn arb_payload_string() -> impl Strategy<Value = String> {
    proptest::string::string_regex(&format!("[ -~]{{0,{MAX_PAYLOAD_LEN}}}"))
        .expect("payload regex must compile")
}

fn arb_tx() -> impl Strategy<Value = Tx> {
    (
        proptest::collection::vec(any::<u8>(), 0..MAX_PUBKEY_LEN),
        arb_from_string(),
        any::<u64>(), // nonce
        any::<u64>(), // max_fee_per_gas
        any::<u64>(), // max_priority_fee_per_gas
        any::<u64>(), // gas_limit
        arb_payload_string(),
        proptest::collection::vec(any::<u8>(), 0..MAX_SIG_LEN),
        any::<u64>(), // chain_id
    )
        .prop_map(
            |(pubkey, from, nonce, max_fee_per_gas, max_priority_fee_per_gas,
              gas_limit, payload, signature, chain_id)| {
                Tx {
                    pubkey,
                    from,
                    nonce,
                    max_fee_per_gas,
                    max_priority_fee_per_gas,
                    gas_limit,
                    payload,
                    signature,
                    chain_id,
                }
            },
        )
}

fn arb_hash32() -> impl Strategy<Value = Hash32> {
    any::<[u8; 32]>().prop_map(Hash32)
}

fn arb_block_header() -> impl Strategy<Value = BlockHeader> {
    (
        any::<u64>(),                                              // height
        any::<u32>(),                                              // round
        arb_hash32(),                                              // prev
        proptest::collection::vec(any::<u8>(), PROPOSER_PK_LEN),   // proposer_pk
        arb_hash32(),                                              // tx_root
        arb_hash32(),                                              // receipts_root
        arb_hash32(),                                              // state_root
        any::<u64>(),                                              // base_fee_per_gas
        any::<u64>(),                                              // gas_used
        any::<u64>(),                                              // intrinsic_gas_used
        any::<u64>(),                                              // exec_gas_used
        any::<u64>(),                                              // vm_gas_used
        any::<u64>(),                                              // evm_gas_used
        any::<u64>(),                                              // chain_id
        any::<u64>(),                                              // timestamp
        any::<u32>(),                                              // protocol_version
    )
        .prop_map(
            |(
                height, round, prev, proposer_pk, tx_root, receipts_root,
                state_root, base_fee_per_gas, gas_used, intrinsic_gas_used,
                exec_gas_used, vm_gas_used, evm_gas_used, chain_id,
                timestamp, protocol_version,
            )| BlockHeader {
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
            },
        )
}

fn arb_block() -> impl Strategy<Value = Block> {
    (
        arb_block_header(),
        proptest::collection::vec(arb_tx(), 0..MAX_TXS_IN_BLOCK),
    )
        .prop_map(|(header, txs)| Block { header, txs })
}

/// A proper receipt strategy. The previous version used
/// `any::<iona::types::Receipt>()` (which requires `Receipt: Arbitrary`)
/// and then ignored the generated value.
fn arb_receipt() -> impl Strategy<Value = Receipt> {
    (
        arb_hash32(),  // tx_hash
        any::<bool>(), // success
        any::<u64>(),  // gas_used
        any::<u64>(),  // intrinsic_gas_used
        any::<u64>(),  // exec_gas_used
        any::<u64>(),  // vm_gas_used
        any::<u64>(),  // evm_gas_used
        any::<u64>(),  // effective_gas_price
        any::<u64>(),  // burned
        any::<u64>(),  // tip
    )
        .prop_map(
            |(tx_hash, success, gas_used, intrinsic_gas_used, exec_gas_used,
              vm_gas_used, evm_gas_used, effective_gas_price, burned, tip)| {
                Receipt {
                    tx_hash,
                    success,
                    gas_used,
                    intrinsic_gas_used,
                    exec_gas_used,
                    vm_gas_used,
                    evm_gas_used,
                    effective_gas_price,
                    burned,
                    tip,
                    error: None,
                    data: None,
                }
            },
        )
}

// ---------------------------------------------------------------------------
// Determinism: same input → same output
// ---------------------------------------------------------------------------

proptest! {
    #[test]
    fn tx_hash_is_deterministic(tx in arb_tx()) {
        prop_assert_eq!(tx_hash(&tx), tx_hash(&tx));
    }

    #[test]
    fn hash_bytes_is_deterministic(
        data in proptest::collection::vec(any::<u8>(), 0..MAX_HASH_DATA_LEN)
    ) {
        prop_assert_eq!(hash_bytes(&data), hash_bytes(&data));
    }

    #[test]
    fn block_id_is_deterministic(block in arb_block()) {
        prop_assert_eq!(block.id(), block.id());
    }

    #[test]
    fn tx_root_is_deterministic(
        txs in proptest::collection::vec(arb_tx(), 0..MAX_TXS_IN_BLOCK)
    ) {
        prop_assert_eq!(tx_root(&txs), tx_root(&txs));
    }

    #[test]
    fn receipts_root_is_deterministic(
        receipts in proptest::collection::vec(arb_receipt(), 0..MAX_RECEIPTS)
    ) {
        prop_assert_eq!(receipts_root(&receipts), receipts_root(&receipts));
    }
}

// ---------------------------------------------------------------------------
// Sensitivity: different input → different output
// ---------------------------------------------------------------------------

proptest! {
    /// Each individual field must affect the transaction hash.
    ///
    /// Without this property, two distinct transactions could hash to
    /// the same value and a Byzantine node could substitute one for
    /// the other without breaking the hash chain.
    #[test]
    fn tx_hash_is_sensitive_to_every_field(tx in arb_tx()) {
        let base = tx_hash(&tx);

        let mut t = tx.clone();
        t.pubkey.push(0xAB);
        prop_assert_ne!(tx_hash(&t), base, "pubkey must affect hash");

        let mut t = tx.clone();
        t.from.push('Z');
        prop_assert_ne!(tx_hash(&t), base, "from must affect hash");

        let mut t = tx.clone();
        t.nonce = t.nonce.wrapping_add(1);
        prop_assert_ne!(tx_hash(&t), base, "nonce must affect hash");

        let mut t = tx.clone();
        t.max_fee_per_gas = t.max_fee_per_gas.wrapping_add(1);
        prop_assert_ne!(tx_hash(&t), base, "max_fee_per_gas must affect hash");

        let mut t = tx.clone();
        t.max_priority_fee_per_gas = t.max_priority_fee_per_gas.wrapping_add(1);
        prop_assert_ne!(tx_hash(&t), base, "max_priority_fee_per_gas must affect hash");

        let mut t = tx.clone();
        t.gas_limit = t.gas_limit.wrapping_add(1);
        prop_assert_ne!(tx_hash(&t), base, "gas_limit must affect hash");

        let mut t = tx.clone();
        t.payload.push('!');
        prop_assert_ne!(tx_hash(&t), base, "payload must affect hash");

        let mut t = tx.clone();
        t.signature.push(0xCD);
        prop_assert_ne!(tx_hash(&t), base, "signature must affect hash");

        let mut t = tx.clone();
        t.chain_id = t.chain_id.wrapping_add(1);
        prop_assert_ne!(tx_hash(&t), base, "chain_id must affect hash");
    }

    /// Every block header field must affect the block ID.
    #[test]
    fn block_id_is_sensitive_to_every_header_field(
        header in arb_block_header(),
        txs in proptest::collection::vec(arb_tx(), 0..MAX_TXS_IN_BLOCK),
    ) {
        let base = Block { header: header.clone(), txs: txs.clone() }.id();

        let mut h = header.clone();
        h.height = h.height.wrapping_add(1);
        prop_assert_ne!(Block { header: h, txs: txs.clone() }.id(), base, "height");

        let mut h = header.clone();
        h.round = h.round.wrapping_add(1);
        prop_assert_ne!(Block { header: h, txs: txs.clone() }.id(), base, "round");

        let mut h = header.clone();
        h.prev.0[0] = h.prev.0[0].wrapping_add(1);
        prop_assert_ne!(Block { header: h, txs: txs.clone() }.id(), base, "prev");

        let mut h = header.clone();
        h.proposer_pk[0] = h.proposer_pk[0].wrapping_add(1);
        prop_assert_ne!(Block { header: h, txs: txs.clone() }.id(), base, "proposer_pk");

        let mut h = header.clone();
        h.tx_root.0[0] = h.tx_root.0[0].wrapping_add(1);
        prop_assert_ne!(Block { header: h, txs: txs.clone() }.id(), base, "tx_root");

        let mut h = header.clone();
        h.receipts_root.0[0] = h.receipts_root.0[0].wrapping_add(1);
        prop_assert_ne!(Block { header: h, txs: txs.clone() }.id(), base, "receipts_root");

        let mut h = header.clone();
        h.state_root.0[0] = h.state_root.0[0].wrapping_add(1);
        prop_assert_ne!(Block { header: h, txs: txs.clone() }.id(), base, "state_root");

        let mut h = header.clone();
        h.base_fee_per_gas = h.base_fee_per_gas.wrapping_add(1);
        prop_assert_ne!(Block { header: h, txs: txs.clone() }.id(), base, "base_fee_per_gas");

        let mut h = header.clone();
        h.gas_used = h.gas_used.wrapping_add(1);
        prop_assert_ne!(Block { header: h, txs: txs.clone() }.id(), base, "gas_used");

        let mut h = header.clone();
        h.intrinsic_gas_used = h.intrinsic_gas_used.wrapping_add(1);
        prop_assert_ne!(Block { header: h, txs: txs.clone() }.id(), base, "intrinsic_gas_used");

        let mut h = header.clone();
        h.exec_gas_used = h.exec_gas_used.wrapping_add(1);
        prop_assert_ne!(Block { header: h, txs: txs.clone() }.id(), base, "exec_gas_used");

        let mut h = header.clone();
        h.vm_gas_used = h.vm_gas_used.wrapping_add(1);
        prop_assert_ne!(Block { header: h, txs: txs.clone() }.id(), base, "vm_gas_used");

        let mut h = header.clone();
        h.evm_gas_used = h.evm_gas_used.wrapping_add(1);
        prop_assert_ne!(Block { header: h, txs: txs.clone() }.id(), base, "evm_gas_used");

        let mut h = header.clone();
        h.chain_id = h.chain_id.wrapping_add(1);
        prop_assert_ne!(Block { header: h, txs: txs.clone() }.id(), base, "chain_id");

        let mut h = header.clone();
        h.timestamp = h.timestamp.wrapping_add(1);
        prop_assert_ne!(Block { header: h, txs: txs.clone() }.id(), base, "timestamp");

        let mut h = header.clone();
        h.protocol_version = h.protocol_version.wrapping_add(1);
        prop_assert_ne!(Block { header: h, txs: txs.clone() }.id(), base, "protocol_version");
    }

    /// Any single-byte change in the input to `hash_bytes` must change
    /// the output. For SHA-256, the probability of a one-byte change
    /// colliding is 2^-256 — below proptest's iteration budget by many
    /// orders of magnitude.
    #[test]
    fn hash_bytes_is_sensitive_to_input(
        data in proptest::collection::vec(any::<u8>(), 1..MAX_HASH_DATA_LEN),
    ) {
        let base = hash_bytes(&data);
        let mut modified = data.clone();
        modified[0] = modified[0].wrapping_add(1);
        prop_assert_ne!(hash_bytes(&modified), base);
    }

    /// Adding or removing a transaction must change the tx root.
    #[test]
    fn tx_root_is_sensitive_to_tx_count(
        txs in proptest::collection::vec(arb_tx(), 1..MAX_TXS_IN_BLOCK),
    ) {
        let base = tx_root(&txs);
        let mut shortened = txs.clone();
        shortened.pop();
        prop_assert_ne!(tx_root(&shortened), base);
    }
}

// ---------------------------------------------------------------------------
// Quorum threshold
// ---------------------------------------------------------------------------

proptest! {
    /// `quorum_threshold` satisfies `2n/3 < t <= n` for `n >= 1`, and
    /// `t == 1` for `n == 0`.
    ///
    /// Computed in `u128` so the bound does not overflow on inputs near
    /// `u64::MAX`.
    #[test]
    fn quorum_threshold_is_byzantine_safe(power in any::<u64>()) {
        let threshold = iona::consensus::quorum_threshold(power);
        if power == 0 {
            prop_assert_eq!(threshold, 1);
        } else {
            let two_thirds = (power as u128) * 2 / 3;
            prop_assert!((threshold as u128) > two_thirds);
            prop_assert!(threshold <= power);
        }
    }

    /// `has_quorum` must agree with `voting >= quorum_threshold(total)`.
    #[test]
    fn has_quorum_matches_threshold(total in any::<u64>(), voting in any::<u64>()) {
        let threshold = iona::consensus::quorum_threshold(total);
        prop_assert_eq!(
            iona::consensus::has_quorum(voting, total),
            voting >= threshold,
        );
    }
}

// ---------------------------------------------------------------------------
// Serialization round-trip
// ---------------------------------------------------------------------------

proptest! {
    #[test]
    fn hash32_serialization_roundtrip(h in arb_hash32()) {
        let json = serde_json::to_string(&h).expect("Hash32 must serialize");
        let restored: Hash32 =
            serde_json::from_str(&json).expect("Hash32 must deserialize");
        prop_assert_eq!(h, restored);
    }
}

// ---------------------------------------------------------------------------
// Non-property checks
//
// Fixed vectors that complement the properties above. Any regression
// here is either a hash change (update `tests/golden_vectors.rs`) or a
// real bug in the primitives.
// ---------------------------------------------------------------------------

#[test]
fn hash32_zero_is_all_zero() {
    assert_eq!(Hash32::zero().0, [0u8; 32]);
}

#[test]
fn tx_hash_of_nonempty_tx_is_nonzero() {
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
    assert_ne!(tx_hash(&tx).0, [0u8; 32]);
}

#[test]
fn block_id_of_nondefault_header_is_nonzero() {
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
        timestamp: 123_456,
        protocol_version: 1,
    };
    assert_ne!(Block { header, txs: vec![] }.id().0, [0u8; 32]);
}

/// Concrete fixed vectors that pin the quorum formula at small `n`.
/// The property test above verifies the bound; these vectors verify the
/// exact values so a rounding-direction change (e.g. `ceil` vs `floor`)
/// is caught.
#[test]
fn quorum_threshold_fixed_vectors() {
    assert_eq!(iona::consensus::quorum_threshold(0), 1);
    assert_eq!(iona::consensus::quorum_threshold(1), 1);
    assert_eq!(iona::consensus::quorum_threshold(2), 2);
    assert_eq!(iona::consensus::quorum_threshold(3), 3);
    assert_eq!(iona::consensus::quorum_threshold(4), 3);
    assert_eq!(iona::consensus::quorum_threshold(5), 4);
}
