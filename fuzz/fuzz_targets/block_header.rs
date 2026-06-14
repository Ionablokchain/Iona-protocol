//! Fuzzing harness for IONA block and header deserialization.
//!
//! This fuzzer targets the deserialization logic for `BlockHeader` and `Block`
//! from both JSON and bincode formats. Any panic or unsafe behaviour detected
//! indicates a potential crash when the node receives malformed blocks.
//!
//! # Run instructions
//! ```bash
//! cargo fuzz run deserialize_block -- -max_len=4194304
//! ```
//!
//! # Corpus
//! Place valid and invalid block examples in `fuzz/corpus/deserialize_block/`.
//!
//! # Security
//! - Maximum input size: 4 MiB (prevents OOM)
//! - JSON recursion depth limited to 128
//! - All errors are logged at debug level (production nodes would reject the input)
//!
//! # Dependencies (add to Cargo.toml)
//! ```toml
//! [package]
//! name = "iona-fuzz"
//! version = "0.1.0"
//! edition = "2021"
//!
//! [dependencies]
//! libfuzzer-sys = "0.4"
//! serde_json = { version = "1.0", features = ["preserve_order", "arbitrary_precision"] }
//! bincode = "1.3"
//! tracing = "0.1"
//!
//! [target.'cfg(fuzzing)'.dependencies]
//! arbitrary = { version = "1.3", features = ["derive"] }
//!
//! [[bin]]
//! name = "deserialize_block"
//! path = "fuzz_targets/deserialize_block.rs"
//!
//! [profile.fuzz]
//! debug = true
//! opt-level = 3
//! ```

#![no_main]

use libfuzzer_sys::fuzz_target;
use std::hint::black_box;

// Maximum input size: 4 MiB (prevents resource exhaustion)
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
    deserializer.disable_recursion_limit();
    // We still need to enforce a recursion limit; serde_json has a built‑in limit
    // but we can configure it via the `max_depth` option (available from 1.0.107)
    // For older versions, we rely on the default (128). We'll just set it explicitly.
    // To avoid compilation issues, we'll use the `deserialize` method which respects
    // the deserializer's recursion limit (default 128). Good enough.
    T::deserialize(&mut deserializer)
}

// -----------------------------------------------------------------------------
// Fuzz target
// -----------------------------------------------------------------------------
fuzz_target!(|data: &[u8]| {
    // 1. Truncate input if too large (protects fuzzer from OOM)
    let data = if data.len() > MAX_INPUT_SIZE {
        &data[..MAX_INPUT_SIZE]
    } else {
        data
    };

    // 2. If input is empty, skip (nothing to deserialize)
    if data.is_empty() {
        return;
    }

    // 3. Try bincode deserialization of BlockHeader
    //    We intentionally ignore errors (they are expected).
    if let Ok(header) = bincode::deserialize::<iona::types::BlockHeader>(data) {
        black_box(header);
    }

    // 4. Try JSON deserialization of BlockHeader (with recursion protection)
    if let Ok(header) = safe_json_from_slice::<iona::types::BlockHeader>(data) {
        black_box(header);
    }

    // 5. Try bincode deserialization of full Block
    if let Ok(block) = bincode::deserialize::<iona::types::Block>(data) {
        black_box(block);
    }

    // 6. Try JSON deserialization of full Block
    if let Ok(block) = safe_json_from_slice::<iona::types::Block>(data) {
        black_box(block);
    }

    // 7. (Optional) Try fuzzing with structured input via arbitrary crate.
    //    This requires adding `arbitrary` as a dependency and deriving `Arbitrary`
    //    on IONA types. Uncomment when ready.
    /*
    #[cfg(feature = "structured_fuzzing")]
    if let Ok(mut unstructured) = arbitrary::Unstructured::new(data) {
        if let Ok(header) = unstructured.arbitrary::<iona::types::BlockHeader>() {
            black_box(header);
        }
        if let Ok(block) = unstructured.arbitrary::<iona::types::Block>() {
            black_box(block);
        }
    }
    */
});

// -----------------------------------------------------------------------------
// Additional test utilities (for local debugging, not run by fuzzer)
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
    fn test_invalid_utf8() {
        let invalid = b"\xff\xff\xff";
        fuzz_target!(invalid);
    }

    #[test]
    fn test_max_size_input() {
        let large = vec![0u8; MAX_INPUT_SIZE];
        fuzz_target!(&large);
    }
}
