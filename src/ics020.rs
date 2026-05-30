//! IONA — ICS-020 Fungible Token Transfer (Quantum Implementation).
//!
//! # Quantum Token Transfer Model
//!
//! Cross-chain token transfers are modeled as quantum teleportation of
//! value states between two blockchain Hilbert spaces. The escrow mechanism
//! creates entanglement between the source and destination chains.
//!
//! # Hamiltonian for Token Transfers
//!
//! ```text
//! Ĥ_ics020 = Ĥ_send + Ĥ_receive + Ĥ_timeout + Ĥ_voucher
//!
//! Ĥ_send    = Σ_t g_t (|locked⟩⟨free|_t + h.c.)
//! Ĥ_receive = Σ_r h_r (|minted⟩⟨burned|_r + h.c.)
//! Ĥ_timeout = Σ_o ω_o |expired_o⟩⟨expired_o|
//! Ĥ_voucher = Σ_v ν_v a†_v a_v
//! ```
//!
//! # Quantum Escrow Mechanism
//!
//! When tokens are sent, they enter a quantum superposition:
//! ```text
//! |ψ_escrow⟩ = α|locked⟩ + β|free⟩
//! ```
//! where |α|² + |β|² = 1. The state collapses to |free⟩ upon successful
//! receipt, or remains |locked⟩ until timeout.
//!
//! # Quantum Voucher Model
//!
//! Vouchers are quantum states representing foreign tokens:
//! ```text
//! |voucher⟩ = U_mint |∅⟩
//! ```
//! with a creation operator a†_v and annihilation operator a_v.

use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap};
use crate::ibc::{ClientId, IbcHeight};
use crate::types::Height;

// -----------------------------------------------------------------------------
// Quantum Constants
// -----------------------------------------------------------------------------

/// Reduced Planck constant (natural units).
const HBAR: f64 = 1.0;

/// Entanglement fidelity for cross-chain transfers.
const TRANSFER_FIDELITY: f64 = 0.999;

/// Coherence decay per transfer operation.
const TRANSFER_DECOHERENCE: f64 = 0.001;

/// Minimum voucher fidelity threshold.
const VOUCHER_FIDELITY_THRESHOLD: f64 = 0.99;

/// Default timeout height offset.
const DEFAULT_TIMEOUT_HEIGHT_OFFSET: u64 = 1000;

// -----------------------------------------------------------------------------
// Quantum IBC Channel Types
// -----------------------------------------------------------------------------

pub type ChannelId = String;
pub type PortId = String;
pub type Denom = String;

/// Quantum IBC channel for token transfers.
///
/// The channel exists in a superposition of states:
/// ```text
/// |channel⟩ = α|init⟩ + β|tryopen⟩ + γ|open⟩ + δ|closed⟩
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Channel {
    pub channel_id: ChannelId,
    pub port_id: PortId,
    pub counterparty_channel: ChannelId,
    pub counterparty_port: PortId,
    pub client_id: ClientId,
    pub state: ChannelState,
    pub ordering: ChannelOrdering,
    /// Quantum coherence of the channel.
    #[serde(default = "default_coherence")]
    pub coherence: f64,
    /// Entanglement fidelity with counterparty.
    #[serde(default = "default_coherence")]
    pub entanglement_fidelity: f64,
}

fn default_coherence() -> f64 {
    1.0
}

/// Channel state — quantum eigenstates.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum ChannelState {
    /// Ground state — channel initializing.
    Init,
    /// First excited state — attempting to open.
    TryOpen,
    /// Operational state — channel is active.
    Open,
    /// Decayed state — channel is closed.
    Closed,
}

/// Channel ordering — quantum statistics.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum ChannelOrdering {
    /// Bosonic: packets can be processed in any order.
    Unordered,
    /// Fermionic: packets must be processed sequentially.
    Ordered,
}

// -----------------------------------------------------------------------------
// Quantum Fungible Token Packet
// -----------------------------------------------------------------------------

/// Quantum fungible token packet — the state vector for a transfer.
///
/// Represents the quantum information being teleported:
/// ```text
/// |packet⟩ = |denom⟩ ⊗ |amount⟩ ⊗ |sender⟩ ⊗ |receiver⟩
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FungibleTokenPacket {
    /// Token denomination (quantum number).
    pub denom: Denom,
    /// Amount to transfer (eigenvalue).
    pub amount: String,
    /// Sender address on source chain.
    pub sender: String,
    /// Receiver address on destination chain.
    pub receiver: String,
    /// Optional memo (quantum note).
    pub memo: String,
    /// Packet coherence.
    #[serde(default = "default_coherence")]
    pub coherence: f64,
}

/// A quantum IBC packet with sequence, routing, and timeout.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Packet {
    /// Sequence number (quantum index).
    pub sequence: u64,
    /// Source port (origin subspace).
    pub source_port: PortId,
    /// Source channel (origin channel).
    pub source_channel: ChannelId,
    /// Destination port (target subspace).
    pub destination_port: PortId,
    /// Destination channel (target channel).
    pub destination_channel: ChannelId,
    /// Packet data (quantum state vector).
    pub data: FungibleTokenPacket,
    /// Timeout height (expiration eigenvalue).
    pub timeout_height: Option<IbcHeight>,
    /// Timeout timestamp (expiration time coordinate).
    pub timeout_timestamp: u64,
    /// Packet fidelity.
    #[serde(default = "default_coherence")]
    pub fidelity: f64,
}

// -----------------------------------------------------------------------------
// Quantum ICS-020 Errors
// -----------------------------------------------------------------------------

/// Errors that can occur during quantum token transfers.
#[derive(Debug, Clone, thiserror::Error)]
pub enum Ics020Error {
    #[error("channel not found: {0}")]
    ChannelNotFound(ChannelId),

    #[error("channel not open (state: {0:?})")]
    ChannelNotOpen(ChannelState),

    #[error("insufficient balance: have {have}, need {need}")]
    InsufficientBalance { have: u64, need: u64 },

    #[error("packet timed out at height {timeout}")]
    PacketTimeout { timeout: IbcHeight },

    #[error("invalid denom: {0}")]
    InvalidDenom(String),

    #[error("packet not found: seq={0}")]
    PacketNotFound(u64),

    #[error("quantum decoherence: fidelity {fidelity} below threshold {threshold}")]
    Decoherence { fidelity: f64, threshold: f64 },

    #[error("entanglement broken: transfer cannot be completed")]
    EntanglementBroken,
}

// -----------------------------------------------------------------------------
// Quantum ICS-020 Transfer Module
// -----------------------------------------------------------------------------

/// Quantum ICS-020 transfer module state.
///
/// Manages the quantum states of all token transfers, escrow,
/// and vouchers across IBC channels.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Ics020State {
    /// Open IBC channels (channel_id → Channel).
    pub channels: BTreeMap<ChannelId, Channel>,
    /// Quantum escrow: tokens in superposition of locked/free.
    pub escrow: BTreeMap<Denom, u64>,
    /// Escrow coherence per denomination.
    pub escrow_coherence: BTreeMap<Denom, f64>,
    /// In-flight packets awaiting acknowledgment.
    pub in_flight: BTreeMap<u64, Packet>,
    /// Sequence counter for outgoing packets.
    pub send_sequence: u64,
    /// Voucher balances for received foreign tokens.
    pub vouchers: HashMap<(Denom, String), u64>,
    /// Voucher coherence per denomination.
    pub voucher_coherence: BTreeMap<Denom, f64>,
    /// Channel sequence counter.
    pub next_channel_seq: u64,
    /// Overall module coherence.
    #[serde(default = "default_coherence")]
    pub coherence: f64,
}

impl Ics020State {
    /// Open a new quantum transfer channel.
    ///
    /// Creates a channel in the |open⟩ state with full coherence.
    pub fn open_channel(
        &mut self,
        port_id: PortId,
        counterparty_channel: ChannelId,
        counterparty_port: PortId,
        client_id: ClientId,
    ) -> ChannelId {
        let channel_id = format!("channel-{}", self.next_channel_seq);
        self.next_channel_seq = self.next_channel_seq.wrapping_add(1);

        self.channels.insert(
            channel_id.clone(),
            Channel {
                channel_id: channel_id.clone(),
                port_id,
                counterparty_channel,
                counterparty_port,
                client_id,
                state: ChannelState::Open,
                ordering: ChannelOrdering::Unordered,
                coherence: 1.0,
                entanglement_fidelity: 1.0,
            },
        );

        self.coherence *= 0.9999;

        tracing::info!(
            channel_id = %channel_id,
            "quantum IBC transfer channel opened"
        );

        channel_id
    }

    /// Send tokens to a remote chain via quantum IBC.
    ///
    /// Locks tokens in quantum escrow and creates an entangled packet.
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
        let channel = self
            .channels
            .get(channel_id)
            .ok_or_else(|| Ics020Error::ChannelNotFound(channel_id.to_string()))?
            .clone();

        if channel.state != ChannelState::Open {
            return Err(Ics020Error::ChannelNotOpen(channel.state.clone()));
        }

        // Check sender balance
        let bal = sender_balances.get(&sender).copied().unwrap_or(0);
        if bal < amount {
            return Err(Ics020Error::InsufficientBalance {
                have: bal,
                need: amount,
            });
        }

        // Lock tokens in quantum escrow
        *sender_balances.entry(sender.clone()).or_insert(0) -= amount;
        *self.escrow.entry(denom.clone()).or_insert(0) += amount;

        // Apply decoherence to escrow
        let esc_coh = self
            .escrow_coherence
            .entry(denom.clone())
            .or_insert(1.0);
        *esc_coh *= 1.0 - TRANSFER_DECOHERENCE;

        // Create quantum packet
        let seq = self.send_sequence;
        self.send_sequence = self.send_sequence.wrapping_add(1);

        let packet = Packet {
            sequence: seq,
            source_port: channel.port_id.clone(),
            source_channel: channel_id.to_string(),
            destination_port: channel.counterparty_port.clone(),
            destination_channel: channel.counterparty_channel.clone(),
            data: FungibleTokenPacket {
                denom: denom.clone(),
                amount: amount.to_string(),
                sender: sender.clone(),
                receiver: receiver.clone(),
                memo: String::new(),
                coherence: 1.0,
            },
            timeout_height,
            timeout_timestamp,
            fidelity: TRANSFER_FIDELITY,
        };

        self.in_flight.insert(seq, packet);
        self.coherence *= 1.0 - TRANSFER_DECOHERENCE;

        tracing::info!(
            channel = %channel_id,
            sender = %sender,
            receiver = %receiver,
            denom = %denom,
            amount = amount,
            seq = seq,
            coherence = self.coherence,
            "quantum ICS-020 transfer sent"
        );

        Ok(seq)
    }

    /// Receive a quantum packet from a remote chain.
    ///
    /// Collapses the escrow superposition or mints quantum vouchers.
    pub fn receive_packet(
        &mut self,
        packet: &FungibleTokenPacket,
        receiver_balances: &mut std::collections::BTreeMap<String, u64>,
        current_height: Height,
    ) -> Result<(), Ics020Error> {
        let amount: u64 = packet
            .amount
            .parse()
            .map_err(|_| Ics020Error::InvalidDenom(packet.amount.clone()))?;

        // Check packet coherence
        if packet.coherence < VOUCHER_FIDELITY_THRESHOLD {
            return Err(Ics020Error::Decoherence {
                fidelity: packet.coherence,
                threshold: VOUCHER_FIDELITY_THRESHOLD,
            });
        }

        // Check if this is a native token return
        let is_native_return = packet.denom.starts_with("transfer/");

        if is_native_return {
            // Quantum escrow unlock: collapse |locked⟩ → |free⟩
            let native_denom = packet
                .denom
                .split('/')
                .last()
                .unwrap_or(&packet.denom)
                .to_string();

            let escrowed = self.escrow.get(&native_denom).copied().unwrap_or(0);

            if escrowed >= amount {
                *self.escrow.entry(native_denom.clone()).or_insert(0) -= amount;
                *receiver_balances
                    .entry(packet.receiver.clone())
                    .or_insert(0) += amount;

                // Update escrow coherence
                if let Some(coh) = self.escrow_coherence.get_mut(&native_denom) {
                    *coh *= 0.999;
                }

                tracing::info!(
                    receiver = %packet.receiver,
                    denom = %native_denom,
                    amount = amount,
                    "quantum ICS-020 native return: escrow unlocked"
                );
            }
        } else {
            // Quantum voucher minting: a†_v |∅⟩ → |voucher⟩
            let voucher_denom = format!("transfer/{}", packet.denom);
            let key = (voucher_denom.clone(), packet.receiver.clone());

            *self.vouchers.entry(key).or_insert(0) += amount;

            // Update voucher coherence
            let v_coh = self
                .voucher_coherence
                .entry(voucher_denom.clone())
                .or_insert(1.0);
            *v_coh *= 0.999;

            tracing::info!(
                receiver = %packet.receiver,
                denom = %voucher_denom,
                amount = amount,
                "quantum ICS-020 voucher minted"
            );
        }

        self.coherence *= 0.9999;

        Ok(())
    }

    /// Handle quantum packet timeout — refund sender.
    ///
    /// Collapses the escrow state back to the sender:
    /// ```text
    /// U_timeout |locked⟩ → |free⟩_sender
    /// ```
    pub fn timeout_packet(
        &mut self,
        seq: u64,
        sender_balances: &mut std::collections::BTreeMap<String, u64>,
        current_height: Height,
    ) -> Result<(), Ics020Error> {
        let packet = self
            .in_flight
            .remove(&seq)
            .ok_or(Ics020Error::PacketNotFound(seq))?;

        // Refund from quantum escrow
        let amount: u64 = packet.data.amount.parse().unwrap_or(0);

        *self
            .escrow
            .entry(packet.data.denom.clone())
            .or_insert(0) = self
            .escrow
            .get(&packet.data.denom)
            .copied()
            .unwrap_or(0)
            .saturating_sub(amount);

        *sender_balances
            .entry(packet.data.sender.clone())
            .or_insert(0) += amount;

        // Update escrow coherence
        if let Some(coh) = self.escrow_coherence.get_mut(&packet.data.denom) {
            *coh *= 0.99; // stronger decoherence on timeout
        }

        self.coherence *= 0.999;

        tracing::warn!(
            seq = seq,
            sender = %packet.data.sender,
            amount = amount,
            coherence = self.coherence,
            "quantum ICS-020 packet timeout — refunded"
        );

        Ok(())
    }

    /// Query voucher balance for a foreign token.
    pub fn voucher_balance(&self, denom_path: &str, addr: &str) -> u64 {
        self.vouchers
            .get(&(denom_path.to_string(), addr.to_string()))
            .copied()
            .unwrap_or(0)
    }

    /// Get escrow coherence for a denomination.
    pub fn escrow_coherence_for(&self, denom: &str) -> f64 {
        self.escrow_coherence
            .get(denom)
            .copied()
            .unwrap_or(1.0)
    }

    /// Get voucher coherence for a denomination.
    pub fn voucher_coherence_for(&self, denom: &str) -> f64 {
        self.voucher_coherence
            .get(denom)
            .copied()
            .unwrap_or(1.0)
    }

    /// Get transfer statistics.
    pub fn stats(&self) -> Ics020Stats {
        Ics020Stats {
            total_channels: self.channels.len(),
            open_channels: self
                .channels
                .values()
                .filter(|c| c.state == ChannelState::Open)
                .count(),
            total_escrow: self.escrow.values().sum(),
            in_flight_packets: self.in_flight.len(),
            total_vouchers: self.vouchers.values().sum(),
            coherence: self.coherence,
        }
    }
}

// -----------------------------------------------------------------------------
// ICS-020 Statistics
// -----------------------------------------------------------------------------

/// Observable statistics for the quantum token transfer module.
#[derive(Debug, Clone)]
pub struct Ics020Stats {
    pub total_channels: usize,
    pub open_channels: usize,
    pub total_escrow: u64,
    pub in_flight_packets: usize,
    pub total_vouchers: u64,
    pub coherence: f64,
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    #[test]
    fn test_send_and_receive_roundtrip() {
        let mut ics = Ics020State::default();
        let mut bals: BTreeMap<String, u64> = BTreeMap::new();
        bals.insert("alice".to_string(), 1_000_000);

        // Open channel
        let ch = ics.open_channel(
            "transfer".into(),
            "channel-42".into(),
            "transfer".into(),
            "cosmoshub-4-0".into(),
        );

        // Send
        let seq = ics
            .send_transfer(
                &ch,
                "alice".to_string(),
                "cosmos1abc".to_string(),
                "uiona".to_string(),
                500_000,
                &mut bals,
                None,
                0,
                1,
            )
            .unwrap();

        assert_eq!(*bals.get("alice").unwrap(), 500_000);
        assert_eq!(*ics.escrow.get("uiona").unwrap(), 500_000);
        assert!(ics.escrow_coherence_for("uiona") < 1.0);

        // Simulate return packet
        let return_packet = FungibleTokenPacket {
            denom: "transfer/uiona".to_string(),
            amount: "500000".to_string(),
            sender: "cosmos1abc".to_string(),
            receiver: "alice".to_string(),
            memo: String::new(),
            coherence: 1.0,
        };

        ics.receive_packet(&return_packet, &mut bals, 10).unwrap();
        assert_eq!(*bals.get("alice").unwrap(), 1_000_000);
    }

    #[test]
    fn test_timeout_refunds_sender() {
        let mut ics = Ics020State::default();
        let mut bals: BTreeMap<String, u64> = BTreeMap::new();
        bals.insert("bob".to_string(), 1_000_000);

        let ch = ics.open_channel(
            "transfer".into(),
            "ch-1".into(),
            "transfer".into(),
            "c-0".into(),
        );

        let seq = ics
            .send_transfer(
                &ch,
                "bob".to_string(),
                "cosmos1xyz".to_string(),
                "uiona".to_string(),
                300_000,
                &mut bals,
                None,
                0,
                1,
            )
            .unwrap();

        ics.timeout_packet(seq, &mut bals, 100).unwrap();
        assert_eq!(*bals.get("bob").unwrap(), 1_000_000);
    }

    #[test]
    fn test_voucher_balance() {
        let mut ics = Ics020State::default();

        let key = ("transfer/uatom".to_string(), "alice".to_string());
        ics.vouchers.insert(key, 500);

        assert_eq!(ics.voucher_balance("transfer/uatom", "alice"), 500);
    }

    #[test]
    fn test_ics020_stats() {
        let mut ics = Ics020State::default();
        ics.open_channel(
            "transfer".into(),
            "ch-1".into(),
            "transfer".into(),
            "c-0".into(),
        );

        let stats = ics.stats();
        assert_eq!(stats.total_channels, 1);
        assert_eq!(stats.open_channels, 1);
        assert!(stats.coherence > 0.99);
    }

    #[test]
    fn test_decoherence_tracking() {
        let mut ics = Ics020State::default();
        let mut bals: BTreeMap<String, u64> = BTreeMap::new();
        bals.insert("carol".to_string(), 1_000_000);

        let ch = ics.open_channel(
            "transfer".into(),
            "ch-1".into(),
            "transfer".into(),
            "c-0".into(),
        );

        let initial_coherence = ics.coherence;

        ics.send_transfer(
            &ch,
            "carol".to_string(),
            "cosmos1def".to_string(),
            "uiona".to_string(),
            100_000,
            &mut bals,
            None,
            0,
            1,
        )
        .unwrap();

        assert!(ics.coherence < initial_coherence);
        assert!(ics.escrow_coherence_for("uiona") < 1.0);
    }
}
