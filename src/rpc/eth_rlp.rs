use rlp::RlpStream;
use crate::rpc::eth_rpc::{Log, Receipt};

fn hex_to_bytes(h: &str) -> Vec<u8> {
    hex::decode(h.trim_start_matches("0x")).unwrap_or_default()
}

pub fn rlp_encode_log(l: &Log) -> Vec<u8> {
    // Log: [address, topics, data]
    let mut s = RlpStream::new_list(3);
    s.append(&hex_to_bytes(&l.address));
    // topics: list of 32-byte values
    s.begin_list(l.topics.len());
    for t in &l.topics {
        s.append(&hex_to_bytes(t));
    }
    s.append(&hex_to_bytes(&l.data));
    s.out().to_vec()
}

pub fn rlp_encode_receipt(r: &Receipt) -> Vec<u8> {
    // Receipt (post-Byzantium): [status, cumulativeGasUsed, logsBloom, logs]
    // NOTE: In Ethereum receipts, status is 0/1 and everything is RLP; bloom is 256 bytes.
    let mut s = RlpStream::new_list(4);

    // status (0/1)
    s.append(&if r.status { 1u8 } else { 0u8 });

    // cumulativeGasUsed
    s.append(&r.cumulative_gas_used);

    // logsBloom (256 bytes)
    s.append(&hex_to_bytes(&r.logs_bloom));

    // logs
    s.begin_list(r.logs.len());
    for l in &r.logs {
        s.append_raw(&rlp_encode_log(l), 1);
    }

    s.out().to_vec()
}


/// Typed receipt envelope per EIP-2718.
/// For London+Shanghai baseline:
/// - legacy tx => legacy receipt (no type prefix)
/// - EIP-1559 tx (0x02) => 0x02 || RLP(payload)
pub fn rlp_encode_typed_receipt(tx_type: u8, r: &Receipt) -> Vec<u8> {
    let inner = rlp_encode_receipt(r);
    match tx_type {
        0x02 => {
            let mut out = Vec::with_capacity(1 + inner.len());
            out.push(0x02);
            out.extend_from_slice(&inner);
            out
        }
        _ => inner,
    }
}
