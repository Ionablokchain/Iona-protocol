use proptest::prelude::*;

use iona::types::{hash_bytes, tx_hash, Tx};

fn arb_tx() -> impl Strategy<Value = Tx> {
    (
        proptest::collection::vec(any::<u8>(), 0..128),
        ".{0,64}",
        any::<u64>(),
        any::<u64>(),
        any::<u64>(),
        any::<u64>(),
        ".{0,256}",
        proptest::collection::vec(any::<u8>(), 0..96),
        any::<u64>(),
    )
        .prop_map(
            |(pubkey, from, nonce, max_fee, max_prio, gas_limit, payload, signature, chain_id)| Tx {
                pubkey,
                from,
                nonce,
                max_fee_per_gas: max_fee,
                max_priority_fee_per_gas: max_prio,
                gas_limit,
                payload,
                signature,
                chain_id,
            },
        )
}

proptest! {
    #[test]
    fn tx_hash_is_deterministic(tx in arb_tx()) {
        let h1 = tx_hash(&tx);
        let h2 = tx_hash(&tx);
        prop_assert_eq!(h1.0, h2.0);
    }

    #[test]
    fn hash_bytes_is_deterministic(data in proptest::collection::vec(any::<u8>(), 0..4096)) {
        let h1 = hash_bytes(&data);
        let h2 = hash_bytes(&data);
        prop_assert_eq!(h1.0, h2.0);
    }
}
