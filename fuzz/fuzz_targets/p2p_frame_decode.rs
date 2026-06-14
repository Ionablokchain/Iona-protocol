//! Fuzzing harness for P2P message deserialization.
//!
//! Fuzzes all message types that can be received over the wire:
//!   - Consensus messages (ConsensusMsg)
//!   - Full blocks (Block)
//!   - Transactions (Tx)
//!   - Length‑prefixed frames (first 4 bytes = payload length, then payload)
//!
//! Any panic indicates a potential crash when a live node receives a malformed packet.
//!
//! # Run instructions
//! ```bash
//! cargo fuzz run p2p_messages -- -max_len=4194304
//! ```
//!
//! # Security
//! - Maximum input size: 4 MiB (prevents OOM)
//! - Length‑prefixed decoding validates bounds to avoid OOB access
//! - All errors are ignored (logged at debug level)
//! - `black_box` prevents compiler optimisations

#![no_main]

use libfuzzer_sys::fuzz_target;
use std::hint::black_box;

// Maximum input size: 4 MiB
const MAX_INPUT_SIZE: usize = 4 * 1024 * 1024;

// -----------------------------------------------------------------------------
// Helper: safe length‑prefixed decoding
// -----------------------------------------------------------------------------
fn decode_length_prefixed(data: &[u8]) -> Option<&[u8]> {
    if data.len() < 4 {
        return None;
    }
    // Read big‑endian length
    let len_bytes = [data[0], data[1], data[2], data[3]];
    let len = u32::from_be_bytes(len_bytes) as usize;
    // Protect against absurd lengths (DoS)
    if len > MAX_INPUT_SIZE || len > data.len().saturating_sub(4) {
        return None;
    }
    Some(&data[4..4 + len])
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

    // 2. Direct deserialization of each message type
    if let Ok(msg) = bincode::deserialize::<iona::consensus::ConsensusMsg>(data) {
        black_box(msg);
    }
    if let Ok(block) = bincode::deserialize::<iona::types::Block>(data) {
        black_box(block);
    }
    if let Ok(tx) = bincode::deserialize::<iona::types::Tx>(data) {
        black_box(tx);
    }

    // 3. Length‑prefixed frame: first 4 bytes = payload length
    if let Some(payload) = decode_length_prefixed(data) {
        // Try to deserialize the payload as a ConsensusMsg
        if let Ok(msg) = bincode::deserialize::<iona::consensus::ConsensusMsg>(payload) {
            black_box(msg);
        }
    }

    // 4. (Optional) Structured fuzzing via `arbitrary` – uncomment when ready
    /*
    #[cfg(feature = "structured_fuzzing")]
    if let Ok(mut unstructured) = arbitrary::Unstructured::new(data) {
        if let Ok(msg) = unstructured.arbitrary::<iona::consensus::ConsensusMsg>() {
            black_box(msg);
        }
        if let Ok(block) = unstructured.arbitrary::<iona::types::Block>() {
            black_box(block);
        }
        if let Ok(tx) = unstructured.arbitrary::<iona::types::Tx>() {
            black_box(tx);
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
    fn test_length_prefixed_invalid() {
        // Length too large (should be ignored)
        let mut data = vec![0xFF, 0xFF, 0xFF, 0xFF, 1, 2, 3];
        fuzz_target!(&data);
        // Length zero (valid empty payload)
        data = vec![0, 0, 0, 0];
        fuzz_target!(&data);
        // Not enough data for full length
        data = vec![0, 0, 0];
        fuzz_target!(&data);
    }

    #[test]
    fn test_valid_bincode_data() {
        // Minimal valid bincode for any type (just an example, will error but not panic)
        let data = bincode::serialize(&iona::consensus::ConsensusMsg::Ping).unwrap();
        fuzz_target!(&data);
    }
}
