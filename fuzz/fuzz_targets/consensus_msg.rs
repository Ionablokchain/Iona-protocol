#![no_main]
use libfuzzer_sys::fuzz_target;

// Fuzz deserialization of ConsensusMsg from both bincode and JSON,
// and perform round-trip checks to ensure serialization symmetry.
// Any panic here = potential crash when receiving malformed consensus messages.
fuzz_target!(|data: &[u8]| {
    use iona::consensus::ConsensusMsg;

    // ---- Bincode round-trip ----
    if let Ok(msg) = bincode::deserialize::<ConsensusMsg>(data) {
        // Optional: basic sanity checks that shouldn't panic
        match &msg {
            ConsensusMsg::Proposal(proposal) => {
                let _ = proposal.block_id; // just touch fields
            }
            ConsensusMsg::Prevote(vote) => {
                let _ = vote.block_id;
            }
            ConsensusMsg::Precommit(vote) => {
                let _ = vote.block_id;
            }
            _ => {} // ignore other variants for now
        }

        // Round-trip: serialize and deserialize again
        if let Ok(serialized) = bincode::serialize(&msg) {
            let msg2 = bincode::deserialize::<ConsensusMsg>(&serialized)
                .expect("bincode roundtrip failed: deserialization error");
            assert_eq!(msg, msg2, "bincode roundtrip produced different message");
        }
    }

    // ---- JSON round-trip ----
    if let Ok(msg) = serde_json::from_slice::<ConsensusMsg>(data) {
        if let Ok(serialized) = serde_json::to_vec(&msg) {
            let msg2 = serde_json::from_slice::<ConsensusMsg>(&serialized)
                .expect("JSON roundtrip failed: deserialization error");
            assert_eq!(msg, msg2, "JSON roundtrip produced different message");
        }
    }
});
