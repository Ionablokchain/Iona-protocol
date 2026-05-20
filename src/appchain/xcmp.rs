//! Cross-Chain Message Passing (XCMP) — native cross-appchain communication.
//!
//! Features:
//! - Message validation (nonce sequencing, fee minimum, payload size limits)
//! - Timeout handling (messages expire after timeout_height)
//! - Acknowledgement tracking (delivery receipts)
//! - Channel-based routing with per-channel nonce tracking
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

pub const MIN_XCMP_FEE: u64 = 100;
pub const MAX_PAYLOAD_SIZE: usize = 65_536; // 64 KiB max payload
pub const MAX_QUEUE_DEPTH: usize = 10_000;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct XcmpMessage {
    pub from_chain:     u64,
    pub to_chain:       u64,
    pub nonce:          u64,
    pub payload:        Vec<u8>,
    pub fee:            u64,
    pub timeout_height: u64,
    pub msg_hash:       [u8; 32], // BLAKE3(from_chain || to_chain || nonce || payload)
}

impl XcmpMessage {
    /// Create a new message with computed hash.
    pub fn new(from_chain: u64, to_chain: u64, nonce: u64, payload: Vec<u8>, fee: u64, timeout_height: u64) -> Self {
        let msg_hash = Self::compute_hash(from_chain, to_chain, nonce, &payload);
        Self { from_chain, to_chain, nonce, payload, fee, timeout_height, msg_hash }
    }

    fn compute_hash(from: u64, to: u64, nonce: u64, payload: &[u8]) -> [u8; 32] {
        let mut h = blake3::Hasher::new();
        h.update(&from.to_le_bytes());
        h.update(&to.to_le_bytes());
        h.update(&nonce.to_le_bytes());
        h.update(payload);
        *h.finalize().as_bytes()
    }

    /// Verify message integrity.
    pub fn verify_integrity(&self) -> bool {
        self.msg_hash == Self::compute_hash(self.from_chain, self.to_chain, self.nonce, &self.payload)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum XcmpInstruction {
    Transfer { asset: String, amount: u128, recipient: String },
    Transact { call_data: Vec<u8>, gas: u64 },
    QueryResponse { query_id: u64, response: Vec<u8> },
}

/// Acknowledgement for a delivered message.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct XcmpAck {
    pub msg_hash:       [u8; 32],
    pub from_chain:     u64,
    pub to_chain:       u64,
    pub success:        bool,
    pub result_data:    Vec<u8>,
}

#[derive(Debug, Default)]
pub struct XcmpQueue {
    pub inbound:        Vec<XcmpMessage>,
    pub outbound:       Vec<XcmpMessage>,
    pub processed:      u64,
    pub timed_out:      u64,
    pub acks:           Vec<XcmpAck>,
    /// Per-channel nonce tracking: (from_chain, to_chain) → last_nonce
    pub channel_nonces: HashMap<(u64, u64), u64>,
    /// Delivered message hashes (replay protection)
    pub delivered:      Vec<[u8; 32]>,
}

impl XcmpQueue {
    /// Validate and send a message. Returns error if validation fails.
    pub fn send(&mut self, msg: XcmpMessage) -> Result<(), &'static str> {
        // Validate
        if msg.from_chain == msg.to_chain { return Err("cannot send to same chain"); }
        if msg.fee < MIN_XCMP_FEE { return Err("fee below minimum"); }
        if msg.payload.len() > MAX_PAYLOAD_SIZE { return Err("payload too large"); }
        if self.outbound.len() >= MAX_QUEUE_DEPTH { return Err("outbound queue full"); }
        if !msg.verify_integrity() { return Err("message hash mismatch"); }

        // Verify nonce sequencing
        let channel = (msg.from_chain, msg.to_chain);
        let expected_nonce = self.channel_nonces.get(&channel).copied().unwrap_or(0) + 1;
        if msg.nonce != expected_nonce { return Err("nonce out of sequence"); }
        self.channel_nonces.insert(channel, msg.nonce);

        tracing::debug!(from = msg.from_chain, to = msg.to_chain, nonce = msg.nonce, "XCMP message queued");
        self.outbound.push(msg);
        Ok(())
    }

    /// Receive an inbound message with validation.
    pub fn receive(&mut self, msg: XcmpMessage) -> Result<(), &'static str> {
        if !msg.verify_integrity() { return Err("message hash mismatch"); }
        if self.delivered.contains(&msg.msg_hash) { return Err("duplicate message (replay)"); }
        if self.inbound.len() >= MAX_QUEUE_DEPTH { return Err("inbound queue full"); }
        self.inbound.push(msg);
        Ok(())
    }

    /// Drain messages for a specific chain, checking timeouts.
    pub fn drain_for_chain(&mut self, chain_id: u64, current_height: u64) -> Vec<XcmpMessage> {
        let (for_chain, rest): (Vec<_>, Vec<_>) = self.inbound.drain(..)
            .partition(|m| m.to_chain == chain_id);
        self.inbound = rest;

        // Separate valid from timed-out
        let (valid, expired): (Vec<_>, Vec<_>) = for_chain.into_iter()
            .partition(|m| current_height <= m.timeout_height);

        // Track timed-out messages
        for m in &expired {
            self.timed_out += 1;
            self.acks.push(XcmpAck {
                msg_hash: m.msg_hash,
                from_chain: m.from_chain,
                to_chain: m.to_chain,
                success: false,
                result_data: b"timeout".to_vec(),
            });
            tracing::warn!(from = m.from_chain, nonce = m.nonce, "XCMP message timed out");
        }

        // Mark valid messages as delivered
        for m in &valid {
            self.delivered.push(m.msg_hash);
        }
        self.processed += valid.len() as u64;
        valid
    }

    /// Acknowledge successful delivery of a message.
    pub fn acknowledge(&mut self, msg_hash: [u8; 32], from_chain: u64, to_chain: u64, result_data: Vec<u8>) {
        self.acks.push(XcmpAck { msg_hash, from_chain, to_chain, success: true, result_data });
    }

    /// Expire all timed-out messages across all chains.
    pub fn expire_timed_out(&mut self, current_height: u64) -> usize {
        let before = self.inbound.len();
        let (expired, remaining): (Vec<_>, Vec<_>) = self.inbound.drain(..)
            .partition(|m| current_height > m.timeout_height);
        self.inbound = remaining;
        for m in &expired {
            self.timed_out += 1;
            self.acks.push(XcmpAck {
                msg_hash: m.msg_hash, from_chain: m.from_chain, to_chain: m.to_chain,
                success: false, result_data: b"timeout".to_vec(),
            });
        }
        before - self.inbound.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn send_and_drain() {
        let mut q = XcmpQueue::default();
        let msg = XcmpMessage::new(1, 2, 1, b"hello".to_vec(), 200, 100);
        assert!(q.send(msg).is_ok());
        let drained = q.drain_for_chain(2, 50);
        assert_eq!(drained.len(), 1);
        assert_eq!(q.processed, 1);
    }

    #[test]
    fn nonce_out_of_sequence() {
        let mut q = XcmpQueue::default();
        let msg = XcmpMessage::new(1, 2, 5, b"skip".to_vec(), 200, 100);
        assert_eq!(q.send(msg), Err("nonce out of sequence"));
    }

    #[test]
    fn timeout_handling() {
        let mut q = XcmpQueue::default();
        let msg = XcmpMessage::new(1, 2, 1, b"data".to_vec(), 200, 10);
        q.channel_nonces.insert((1, 2), 0); // reset so nonce 1 works
        assert!(q.send(msg).is_ok());
        // Move to outbound; simulate receiving
        let out = q.outbound.pop().unwrap();
        assert!(q.receive(out).is_ok());
        let drained = q.drain_for_chain(2, 50); // height 50 > timeout 10
        assert!(drained.is_empty()); // timed out
        assert_eq!(q.timed_out, 1);
    }

    #[test]
    fn replay_protection() {
        let mut q = XcmpQueue::default();
        let msg = XcmpMessage::new(1, 2, 1, b"data".to_vec(), 200, 100);
        assert!(q.receive(msg.clone()).is_ok());
        q.drain_for_chain(2, 50); // marks as delivered
        assert_eq!(q.receive(msg), Err("duplicate message (replay)"));
    }

    #[test]
    fn fee_below_minimum() {
        let mut q = XcmpQueue::default();
        let msg = XcmpMessage::new(1, 2, 1, b"data".to_vec(), 10, 100);
        assert_eq!(q.send(msg), Err("fee below minimum"));
    }
}
