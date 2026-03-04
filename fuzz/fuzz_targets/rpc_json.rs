#![no_main]
use libfuzzer_sys::fuzz_target;

// Fuzz RPC JSON deserialization paths.
// Tests that malformed JSON never causes panics in any RPC-facing type.
fuzz_target!(|data: &[u8]| {
    // Transaction
    let _ = serde_json::from_slice::<iona::types::Tx>(data);
    // Block
    let _ = serde_json::from_slice::<iona::types::Block>(data);
    // BlockHeader
    let _ = serde_json::from_slice::<iona::types::BlockHeader>(data);
    // Receipt
    let _ = serde_json::from_slice::<iona::types::Receipt>(data);
    // NodeConfig
    let _ = serde_json::from_slice::<iona::config::NodeConfig>(data);
    // NodeMeta
    let _ = serde_json::from_slice::<iona::storage::meta::NodeMeta>(data);
});
