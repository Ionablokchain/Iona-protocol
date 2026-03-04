#![no_main]
use libfuzzer_sys::fuzz_target;

// Fuzz the P2P message deserialization path.
// Any panic here = crash of a live node receiving a malicious packet.
fuzz_target!(|data: &[u8]| {
    // Attempt to deserialize as every P2P message type that can arrive over the wire.
    let _ = bincode::deserialize::<iona::consensus::ConsensusMsg>(data);
    let _ = bincode::deserialize::<iona::types::Block>(data);
    let _ = bincode::deserialize::<iona::types::Tx>(data);
    // Length-prefixed frame: first 4 bytes = payload length, rest = payload.
    if data.len() >= 4 {
        let len = u32::from_be_bytes([data[0], data[1], data[2], data[3]]) as usize;
        if let Some(payload) = data.get(4..4 + len.min(data.len() - 4)) {
            let _ = bincode::deserialize::<iona::consensus::ConsensusMsg>(payload);
        }
    }
});

