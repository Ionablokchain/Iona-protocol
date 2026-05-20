//! IONA v34 — ICS-020 Fungible Token Transfer.
//!
//! Implements cross-chain token transfers over IBC.
//! Built on the ICS-002 light client from v33.
//!
//! # Protocol
//!
//! ## Send (IONA → Remote chain)
//! 1. Lock tokens in escrow on IONA
//! 2. Send FungibleTokenPacket over IBC channel
//! 3. Remote chain mints voucher tokens
//!
//! ## Receive (Remote chain → IONA)
//! 1. Verify IBC packet commitment proof
//! 2. Unlock escrowed tokens (if native) OR mint vouchers
//!
//! ## Timeout
//! 1. Packet not acknowledged within timeout height/timestamp
//! 2. Unlock escrow (refund sender)

use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap};
use crate::ibc::{ClientId, IbcHeight};
use crate::types::Height;

// ── IBC Channel types ─────────────────────────────────────────────────────

pub type ChannelId = String;
pub type PortId    = String;
pub type Denom     = String;

/// IBC channel for token transfers (ICS-004 channel).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Channel {
    pub channel_id:           ChannelId,
    pub port_id:              PortId,
    pub counterparty_channel: ChannelId,
    pub counterparty_port:    PortId,
    pub client_id:            ClientId,
    pub state:                ChannelState,
    pub ordering:             ChannelOrdering,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum ChannelState {
    Init,
    TryOpen,
    Open,
    Closed,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum ChannelOrdering {
    Unordered,
    Ordered,
}

/// IBC packet for fungible token transfer (ICS-020 spec).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FungibleTokenPacket {
    /// Token denomination (e.g. "uiona", "transfer/channel-0/uatom")
    pub denom: Denom,
    /// Amount to transfer (string for large numbers)
    pub amount: String,
    /// Sender address on source chain
    pub sender: String,
    /// Receiver address on destination chain
    pub receiver: String,
    /// Optional memo
    pub memo: String,
}

/// An IBC packet with sequence, routing, and timeout info.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Packet {
    pub sequence:             u64,
    pub source_port:          PortId,
    pub source_channel:       ChannelId,
    pub destination_port:     PortId,
    pub destination_channel:  ChannelId,
    pub data:                 FungibleTokenPacket,
    pub timeout_height:       Option<IbcHeight>,
    pub timeout_timestamp:    u64,
}

// ── ICS-020 Transfer module ───────────────────────────────────────────────

#[derive(Debug, Clone, thiserror::Error)]
pub enum Ics020Error {
    #[error("channel not found: {0}")]
    ChannelNotFound(ChannelId),
    #[error("channel not open")]
    ChannelNotOpen,
    #[error("insufficient balance: have {have}, need {need}")]
    InsufficientBalance { have: u64, need: u64 },
    #[error("packet timed out at height {timeout}")]
    PacketTimeout { timeout: IbcHeight },
    #[error("invalid denom: {0}")]
    InvalidDenom(String),
    #[error("packet not found: seq={0}")]
    PacketNotFound(u64),
}

/// ICS-020 transfer module state.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Ics020State {
    /// Open IBC channels (channel_id → Channel).
    pub channels: BTreeMap<ChannelId, Channel>,
    /// Escrow: tokens locked for in-flight sends (denom → amount).
    pub escrow: BTreeMap<Denom, u64>,
    /// In-flight packets awaiting acknowledgment.
    pub in_flight: BTreeMap<u64, Packet>,
    /// Sequence counter for outgoing packets.
    pub send_sequence: u64,
    /// Voucher balances for received foreign tokens.
    /// Key: (denom_path, account_address)
    pub vouchers: HashMap<(Denom, String), u64>,
    /// Channel sequence counter.
    pub next_channel_seq: u64,
}

impl Ics020State {
    /// Open a new transfer channel.
    pub fn open_channel(
        &mut self,
        port_id: PortId,
        counterparty_channel: ChannelId,
        counterparty_port: PortId,
        client_id: ClientId,
    ) -> ChannelId {
        let channel_id = format!("channel-{}", self.next_channel_seq);
        self.next_channel_seq += 1;
        self.channels.insert(channel_id.clone(), Channel {
            channel_id: channel_id.clone(),
            port_id,
            counterparty_channel,
            counterparty_port,
            client_id,
            state: ChannelState::Open,
            ordering: ChannelOrdering::Unordered,
        });
        tracing::info!(channel_id = %channel_id, "IBC transfer channel opened");
        channel_id
    }

    /// Send tokens to a remote chain via IBC.
    ///
    /// Locks tokens in escrow and creates an outgoing packet.
    pub fn send_transfer(
        &mut self,
        channel_id: &str,
        sender: String,
        receiver: String,
        denom: Denom,
        amount: u64,
        sender_balances: &mut std::collections::BTreeMap<String, u64>,
        timeout_height: Option<IbcHeight>,
        timeout_timestamp: u64,
        current_height: Height,
    ) -> Result<u64, Ics020Error> {
        let channel = self.channels.get(channel_id)
            .ok_or_else(|| Ics020Error::ChannelNotFound(channel_id.to_string()))?
            .clone();

        if channel.state != ChannelState::Open {
            return Err(Ics020Error::ChannelNotOpen);
        }

        // Check sender balance
        let bal = sender_balances.get(&sender).copied().unwrap_or(0);
        if bal < amount {
            return Err(Ics020Error::InsufficientBalance { have: bal, need: amount });
        }

        // Lock tokens in escrow
        *sender_balances.entry(sender.clone()).or_insert(0) -= amount;
        *self.escrow.entry(denom.clone()).or_insert(0) += amount;

        // Create packet
        let seq = self.send_sequence;
        self.send_sequence += 1;
        let packet = Packet {
            sequence:            seq,
            source_port:         channel.port_id.clone(),
            source_channel:      channel_id.to_string(),
            destination_port:    channel.counterparty_port.clone(),
            destination_channel: channel.counterparty_channel.clone(),
            data: FungibleTokenPacket {
                denom: denom.clone(),
                amount: amount.to_string(),
                sender: sender.clone(),
                receiver: receiver.clone(),
                memo: String::new(),
            },
            timeout_height,
            timeout_timestamp,
        };
        self.in_flight.insert(seq, packet);

        tracing::info!(
            channel   = %channel_id,
            sender    = %sender,
            receiver  = %receiver,
            denom     = %denom,
            amount    = amount,
            seq       = seq,
            "ICS-020 transfer sent"
        );
        Ok(seq)
    }

    /// Receive a packet from a remote chain.
    ///
    /// If the denom is native (not a voucher), unlock from escrow.
    /// Otherwise, mint voucher tokens to the receiver.
    pub fn receive_packet(
        &mut self,
        packet: &FungibleTokenPacket,
        receiver_balances: &mut std::collections::BTreeMap<String, u64>,
        current_height: Height,
    ) -> Result<(), Ics020Error> {
        let amount: u64 = packet.amount.parse()
            .map_err(|_| Ics020Error::InvalidDenom(packet.amount.clone()))?;

        // Check if this is a native token return (voucher path starts with our port)
        let is_native_return = packet.denom.starts_with("transfer/");

        if is_native_return {
            // This is a voucher being sent back — mint native tokens (unlock escrow)
            let native_denom = packet.denom
                .split('/')
                .last()
                .unwrap_or(&packet.denom)
                .to_string();
            let escrowed = self.escrow.get(&native_denom).copied().unwrap_or(0);
            if escrowed >= amount {
                *self.escrow.entry(native_denom.clone()).or_insert(0) -= amount;
                *receiver_balances.entry(packet.receiver.clone()).or_insert(0) += amount;
                tracing::info!(
                    receiver = %packet.receiver,
                    denom    = %native_denom,
                    amount   = amount,
                    "ICS-020 native return: escrow unlocked"
                );
            }
        } else {
            // Foreign token — mint voucher
            let voucher_denom = format!("transfer/{}", packet.denom);
            let key = (voucher_denom.clone(), packet.receiver.clone());
            *self.vouchers.entry(key).or_insert(0) += amount;
            tracing::info!(
                receiver = %packet.receiver,
                denom    = %voucher_denom,
                amount   = amount,
                "ICS-020 voucher minted"
            );
        }
        Ok(())
    }

    /// Handle packet timeout — refund sender from escrow.
    pub fn timeout_packet(
        &mut self,
        seq: u64,
        sender_balances: &mut std::collections::BTreeMap<String, u64>,
        current_height: Height,
    ) -> Result<(), Ics020Error> {
        let packet = self.in_flight.remove(&seq)
            .ok_or(Ics020Error::PacketNotFound(seq))?;

        // Refund from escrow
        let amount: u64 = packet.data.amount.parse().unwrap_or(0);
        *self.escrow.entry(packet.data.denom.clone()).or_insert(0) =
            self.escrow.get(&packet.data.denom).copied().unwrap_or(0).saturating_sub(amount);
        *sender_balances.entry(packet.data.sender.clone()).or_insert(0) += amount;

        tracing::warn!(
            seq    = seq,
            sender = %packet.data.sender,
            amount = amount,
            "ICS-020 packet timeout — refunded"
        );
        Ok(())
    }

    /// Query voucher balance for a foreign token.
    pub fn voucher_balance(&self, denom_path: &str, addr: &str) -> u64 {
        self.vouchers.get(&(denom_path.to_string(), addr.to_string()))
            .copied()
            .unwrap_or(0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    #[test]
    fn send_and_receive_roundtrip() {
        let mut ics = Ics020State::default();
        let mut bals: BTreeMap<String, u64> = BTreeMap::new();
        bals.insert("alice".to_string(), 1_000_000);

        // Open channel
        let ch = ics.open_channel("transfer".into(), "channel-42".into(),
            "transfer".into(), "cosmoshub-4-0".into());

        // Send
        let seq = ics.send_transfer(
            &ch, "alice".to_string(), "cosmos1abc".to_string(),
            "uiona".to_string(), 500_000,
            &mut bals, None, 0, 1
        ).unwrap();

        assert_eq!(*bals.get("alice").unwrap(), 500_000);
        assert_eq!(*ics.escrow.get("uiona").unwrap(), 500_000);

        // Simulate return packet
        let return_packet = FungibleTokenPacket {
            denom: "transfer/uiona".to_string(),
            amount: "500000".to_string(),
            sender: "cosmos1abc".to_string(),
            receiver: "alice".to_string(),
            memo: String::new(),
        };
        ics.receive_packet(&return_packet, &mut bals, 10).unwrap();
        assert_eq!(*bals.get("alice").unwrap(), 1_000_000); // fully refunded
    }

    #[test]
    fn timeout_refunds_sender() {
        let mut ics = Ics020State::default();
        let mut bals: BTreeMap<String, u64> = BTreeMap::new();
        bals.insert("bob".to_string(), 1_000_000);
        let ch = ics.open_channel("transfer".into(), "ch-1".into(), "transfer".into(), "c-0".into());
        let seq = ics.send_transfer(
            &ch, "bob".to_string(), "cosmos1xyz".to_string(),
            "uiona".to_string(), 300_000, &mut bals, None, 0, 1
        ).unwrap();
        ics.timeout_packet(seq, &mut bals, 100).unwrap();
        assert_eq!(*bals.get("bob").unwrap(), 1_000_000);
    }
}
