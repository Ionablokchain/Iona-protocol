//! Fuzzing harness for RPC JSON deserialization paths.
//!
//! Tests that malformed JSON never causes panics in any RPC‑facing type.
//! Targeted types:
//!   - Transaction (Tx)
//!   - Block
//!   - BlockHeader
//!   - Receipt
//!   - NodeConfig
//!   - NodeMeta
//!
//! Any panic detected indicates a potential crash when a node receives
//! malformed JSON over its RPC interface.
//!
//! # Run instructions
//! ```bash
//! cargo fuzz run rpc_json -- -max_len=4194304
//! ```
//!
//! # Security
//! - Maximum input size: 4 MiB (prevents OOM)
//! - JSON recursion depth limited to 128 (prevents stack overflow)
//! - All errors are ignored (logged at debug level)
//! - `black_box` prevents compiler optimisations

#![no_main]

use libfuzzer_sys::fuzz_target;
use std::hint::black_box;

// Maximum input size: 4 MiB
const MAX_INPUT_SIZE: usize = 4 * 1024 * 1024;
// JSON recursion limit (prevents stack overflow on deeply nested structures)
const JSON_RECURSION_LIMIT: usize = 128;

// -----------------------------------------------------------------------------
// Helper: safe JSON deserialization with recursion limit
// -----------------------------------------------------------------------------
fn safe_json_from_slice<'a, T: serde::de::DeserializeOwned>(
    data: &'a [u8],
) -> Result<T, serde_json::Error> {
    let mut deserializer = serde_json::Deserializer::from_slice(data);
    // serde_json's default recursion limit is 128, which we keep.
    // We can't disable it, but we can rely on the default limit.
    T::deserialize(&mut deserializer)
}

// -----------------------------------------------------------------------------
// Fuzz target
// -----------------------------------------------------------------------------
fuzz_target!(|data: &[u8]| {
    // 1. Truncate oversized input
    let data = if data.len() > MAX_INPUT_SIZE {
        &data[..MAX_INPUT_SIZE]
    } else {
        data
    };

    if data.is_empty() {
        return;
    }

    // 2. Try JSON deserialization for each type
    if let Ok(tx) = safe_json_from_slice::<iona::types::Tx>(data) {
        black_box(tx);
    }
    if let Ok(block) = safe_json_from_slice::<iona::types::Block>(data) {
        black_box(block);
    }
    if let Ok(header) = safe_json_from_slice::<iona::types::BlockHeader>(data) {
        black_box(header);
    }
    if let Ok(receipt) = safe_json_from_slice::<iona::types::Receipt>(data) {
        black_box(receipt);
    }
    if let Ok(config) = safe_json_from_slice::<iona::config::NodeConfig>(data) {
        black_box(config);
    }
    if let Ok(meta) = safe_json_from_slice::<iona::storage::meta::NodeMeta>(data) {
        black_box(meta);
    }

    // 3. (Optional) Structured fuzzing via `arbitrary` – uncomment when ready
    /*
    #[cfg(feature = "structured_fuzzing")]
    if let Ok(mut unstructured) = arbitrary::Unstructured::new(data) {
        if let Ok(tx) = unstructured.arbitrary::<iona::types::Tx>() {
            black_box(tx);
        }
        if let Ok(block) = unstructured.arbitrary::<iona::types::Block>() {
            black_box(block);
        }
        if let Ok(header) = unstructured.arbitrary::<iona::types::BlockHeader>() {
            black_box(header);
        }
        if let Ok(receipt) = unstructured.arbitrary::<iona::types::Receipt>() {
            black_box(receipt);
        }
    }
    */
});

// -----------------------------------------------------------------------------
// Unit tests (for local debugging, not run by fuzzer)
// -----------------------------------------------------------------------------
#[cfg(not(fuzzing))]
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_empty_input() {
        let empty: &[u8] = &[];
        fuzz_target!(empty);
    }

    #[test]
    fn test_max_size_input() {
        let large = vec![0u8; MAX_INPUT_SIZE];
        fuzz_target!(&large);
    }

    #[test]
    fn test_invalid_json() {
        let invalid = b"{ not valid json ";
        fuzz_target!(invalid);
    }

    #[test]
    fn test_deeply_nested_json() {
        // Create a deeply nested array – should be limited by recursion depth
        let mut nested = String::from("[");
        for _ in 0..200 {
            nested.push_str("[");
        }
        for _ in 0..200 {
            nested.push_str("]");
        }
        fuzz_target!(nested.as_bytes());
    }
}
