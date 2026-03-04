#![no_main]
use libfuzzer_sys::fuzz_target;

// Fuzz BlockHeader deserialization from both JSON and bincode.
// Any panic here = potential crash when receiving malformed block headers.
fuzz_target!(|data: &[u8]| {
    // Try bincode deserialization
    let _ = bincode::deserialize::<iona::types::BlockHeader>(data);
    // Try JSON deserialization
    let _ = serde_json::from_slice::<iona::types::BlockHeader>(data);
    // Try full Block deserialization
    let _ = bincode::deserialize::<iona::types::Block>(data);
    let _ = serde_json::from_slice::<iona::types::Block>(data);
});
