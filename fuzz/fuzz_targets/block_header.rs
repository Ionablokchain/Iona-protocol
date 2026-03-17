#![no_main]
use libfuzzer_sys::fuzz_target;

// Fuzz BlockHeader and Block deserialization from both JSON and bincode,
// plus round-trip checks to ensure serialization symmetry.
// Any panic here = potential crash when receiving malformed block headers.
fuzz_target!(|data: &[u8]| {
    use iona::types::{Block, BlockHeader};

    // ---- Bincode round-trip for BlockHeader ----
    if let Ok(header) = bincode::deserialize::<BlockHeader>(data) {
        // Basic invariant checks (these should never panic)
        if header.height > 1_000_000_000 {
            // Just a sanity check – no panic expected, but we can call a derived method
            let _ = header.id(); // This computes hash, must not panic
        }

        // Round-trip: serialize and deserialize again
        if let Ok(serialized) = bincode::serialize(&header) {
            let header2 = bincode::deserialize::<BlockHeader>(&serialized)
                .expect("bincode roundtrip failed: deserialization error");
            // Optionally compare the two headers (debug assert, but we want to catch panics)
            assert_eq!(header, header2, "bincode roundtrip produced different header");
        }
    }

    // ---- JSON round-trip for BlockHeader ----
    if let Ok(header) = serde_json::from_slice::<BlockHeader>(data) {
        if let Ok(serialized) = serde_json::to_vec(&header) {
            let header2 = serde_json::from_slice::<BlockHeader>(&serialized)
                .expect("JSON roundtrip failed: deserialization error");
            assert_eq!(header, header2, "JSON roundtrip produced different header");
        }
    }

    // ---- Bincode round-trip for full Block ----
    if let Ok(block) = bincode::deserialize::<Block>(data) {
        // Basic consistency: block ID should be derived from header
        let computed_id = block.id();
        assert_eq!(computed_id, block.header.id(), "block.id() != header.id()");

        if let Ok(serialized) = bincode::serialize(&block) {
            let block2 = bincode::deserialize::<Block>(&serialized)
                .expect("bincode block roundtrip failed");
            assert_eq!(block, block2, "bincode block roundtrip mismatch");
        }
    }

    // ---- JSON round-trip for full Block ----
    if let Ok(block) = serde_json::from_slice::<Block>(data) {
        if let Ok(serialized) = serde_json::to_vec(&block) {
            let block2 = serde_json::from_slice::<Block>(&serialized)
                .expect("JSON block roundtrip failed");
            assert_eq!(block, block2, "JSON block roundtrip mismatch");
        }
    }
});
