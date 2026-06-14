//! Fuzzing harness for IONA consensus message deserialization (bincode).
//!
//! Targets `ConsensusMsg` deserialization from bincode format.
//! Any panic detected indicates a potential crash when the node receives
//! malformed consensus messages (prevote, precommit, proposal, etc.).
//!
//! # Run instructions
//! ```bash
//! cargo fuzz run consensus_msg -- -max_len=4194304
//! ```
//!
//! # Security
//! - Maximum input size: 4 MiB (prevents OOM)
//! - All errors are ignored (logged at debug level)
//! - `black_box` prevents compiler optimisations that would skip the fuzzing logic

#![no_main]

use libfuzzer_sys::fuzz_target;
use std::hint::black_box;

// Maximum input size: 4 MiB (same as block fuzzer)
const MAX_INPUT_SIZE: usize = 4 * 1024 * 1024;

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

    // 2. Skip empty input
    if data.is_empty() {
        return;
    }

    // 3. Try bincode deserialization of ConsensusMsg
    if let Ok(msg) = bincode::deserialize::<iona::consensus::ConsensusMsg>(data) {
        black_box(msg);
    }

    // 4. (Optional) Structured fuzzing via `arbitrary` – uncomment when enabled
    /*
    #[cfg(feature = "structured_fuzzing")]
    if let Ok(mut unstructured) = arbitrary::Unstructured::new(data) {
        if let Ok(msg) = unstructured.arbitrary::<iona::consensus::ConsensusMsg>() {
            black_box(msg);
        }
    }
    */
});

// -----------------------------------------------------------------------------
// Additional tests (for local debugging, not run by fuzzer)
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
    fn test_invalid_data() {
        let invalid = b"not bincode";
        fuzz_target!(invalid);
    }
}
