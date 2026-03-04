use crate::types::Tx;

pub fn derive_address(pubkey: &[u8]) -> String {
    let h = blake3::hash(pubkey);
    hex::encode(&h.as_bytes()[..20])
}

pub fn tx_sign_bytes(tx: &Tx) -> Vec<u8> {
    serde_json::to_vec(&(
        "iona-tx-v1",
        tx.chain_id,
        &tx.pubkey,
        tx.nonce,
        tx.max_fee_per_gas,
        tx.max_priority_fee_per_gas,
        tx.gas_limit,
        &tx.payload,
    )).unwrap_or_default()
}
