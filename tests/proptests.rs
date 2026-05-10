//! Property‑based tests for IONA core types.
//!
//! These tests use `proptest` to verify that critical functions are
//! deterministic across a wide range of random inputs.
//!
//! Run with: `cargo test --test proptest`

use proptest::prelude::*;
use iona::types::{hash_bytes, tx_hash, Tx};

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

/// Character set for sender address strings (alphanumeric and underscore).
const FROM_CHARSET: &str = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_";

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

    /// `hash_bytes` must return the same hash for the same byte slice.
    #[test]
    fn hash_bytes_is_deterministic(data in proptest::collection::vec(any::<u8>(), 0..4096)) {
        let hash1 = hash_bytes(&data);
        let hash2 = hash_bytes(&data);
        prop_assert_eq!(hash1.0, hash2.0);
    }
}
