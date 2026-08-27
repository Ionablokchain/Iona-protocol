//! IONA — ICS-020 Fungible Token Transfer (Quantum Implementation).
//!
//! # Quantum Token Transfer Model
//!
//! Cross-chain token transfers are modeled as quantum teleportation of
//! value states between two blockchain Hilbert spaces. The escrow mechanism
//! creates entanglement between the source and destination chains.
//!
//! # Production Features
//! - Thread‑safe transfer management with `parking_lot::Mutex`.
//! - Persistent state with atomic writes and file locking (`flock`).
//! - Configurable parameters with validation.
//! - Comprehensive metrics and statistics.
//! - Validation of packets, channels, and transfers.
//! - Proper error handling with descriptive variants.
//! - Structured logging with `tracing`.
//! - Prometheus metrics for observability.

use crate::ibc::{ClientId, IbcHeight};
use crate::types::Height;
use fs2::FileExt;
use parking_lot::Mutex;
use prometheus::{register_counter, register_gauge, Counter, Gauge};
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, HashMap},
    fs::{self, File, OpenOptions},
    io::{BufReader, BufWriter, Write},
    path::{Path, PathBuf},
    sync::Arc,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use thiserror::Error;
use tracing::{debug, error, info, warn};

// -----------------------------------------------------------------------------
// Quantum Constants
// -----------------------------------------------------------------------------

/// Reduced Planck constant (natural units).
const HBAR: f64 = 1.0;

/// Default entanglement fidelity for cross-chain transfers.
const DEFAULT_TRANSFER_FIDELITY: f64 = 0.999;

/// Default coherence decay per transfer operation.
const DEFAULT_TRANSFER_DECOHERENCE: f64 = 0.001;

/// Default minimum voucher fidelity threshold.
const DEFAULT_VOUCHER_FIDELITY_THRESHOLD: f64 = 0.99;

/// Default timeout height offset.
const DEFAULT_TIMEOUT_HEIGHT_OFFSET: u64 = 1000;

/// Lock timeout in seconds.
const LOCK_TIMEOUT_SECS: u64 = 10;

/// Temporary file extension for atomic writes.
const TEMP_EXT: &str = ".tmp";

/// Current serialization version.
const CURRENT_VERSION: u32 = 1;

/// Default maximum packet age before forced timeout.
const DEFAULT_MAX_PACKET_AGE_SECS: u64 = 3600;

// -----------------------------------------------------------------------------
// Configuration
// -----------------------------------------------------------------------------

/// Configuration for the ICS-020 transfer module.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Ics020Config {
    /// Minimum fidelity required for packet processing (0.0 – 1.0).
    pub min_packet_fidelity: f64,
    /// Minimum voucher fidelity threshold (0.0 – 1.0).
    pub min_voucher_fidelity: f64,
    /// Decoherence rate per transfer operation.
    pub decoherence_rate: f64,
    /// Default timeout height offset for new transfers.
    pub default_timeout_height_offset: u64,
    /// Maximum packet age in seconds before timeout.
    pub max_packet_age_secs: u64,
    /// Whether to persist state to disk.
    pub persist_state: bool,
    /// Lock timeout in seconds.
    pub lock_timeout_secs: u64,
    /// Whether to enable Prometheus metrics.
    pub enable_metrics: bool,
}

impl Default for Ics020Config {
    fn default() -> Self {
        Self {
            min_packet_fidelity: DEFAULT_TRANSFER_FIDELITY,
            min_voucher_fidelity: DEFAULT_VOUCHER_FIDELITY_THRESHOLD,
            decoherence_rate: DEFAULT_TRANSFER_DECOHERENCE,
            default_timeout_height_offset: DEFAULT_TIMEOUT_HEIGHT_OFFSET,
            max_packet_age_secs: DEFAULT_MAX_PACKET_AGE_SECS,
            persist_state: true,
            lock_timeout_secs: LOCK_TIMEOUT_SECS,
            enable_metrics: true,
        }
    }
}

impl Ics020Config {
    /// Validate the configuration.
    pub fn validate(&self) -> Result<(), String> {
        if !(0.0..=1.0).contains(&self.min_packet_fidelity) {
            return Err("min_packet_fidelity must be between 0.0 and 1.0".into());
        }
        if !(0.0..=1.0).contains(&self.min_voucher_fidelity) {
            return Err("min_voucher_fidelity must be between 0.0 and 1.0".into());
        }
        if !(0.0..=1.0).contains(&self.decoherence_rate) {
            return Err("decoherence_rate must be between 0.0 and 1.0".into());
        }
        if self.default_timeout_height_offset == 0 {
            return Err("default_timeout_height_offset must be > 0".into());
        }
        if self.max_packet_age_secs == 0 {
            return Err("max_packet_age_secs must be > 0".into());
        }
        if self.lock_timeout_secs == 0 {
            return Err("lock_timeout_secs must be > 0".into());
        }
        Ok(())
    }
}

// -----------------------------------------------------------------------------
// Metrics
// -----------------------------------------------------------------------------

/// Metrics for the ICS-020 transfer module.
#[derive(Clone)]
pub struct Ics020Metrics {
    pub transfers_sent: Counter,
    pub transfers_received: Counter,
    pub transfers_timed_out: Counter,
    pub channels_opened: Counter,
    pub packets_acknowledged: Counter,
    pub total_escrow: Gauge,
    pub in_flight_packets: Gauge,
    pub voucher_total: Gauge,
    pub module_coherence: Gauge,
}

impl Ics020Metrics {
    /// Create and register metrics with the global Prometheus registry.
    pub fn new() -> Result<Self, prometheus::Error> {
        Ok(Self {
            transfers_sent: register_counter!(
                "iona_ics020_transfers_sent_total",
                "Total transfers sent"
            )?,
            transfers_received: register_counter!(
                "iona_ics020_transfers_received_total",
                "Total transfers received"
            )?,
            transfers_timed_out: register_counter!(
                "iona_ics020_transfers_timed_out_total",
                "Total transfers timed out"
            )?,
            channels_opened: register_counter!(
                "iona_ics020_channels_opened_total",
                "Total channels opened"
            )?,
            packets_acknowledged: register_counter!(
                "iona_ics020_packets_acknowledged_total",
                "Total packets acknowledged"
            )?,
            total_escrow: register_gauge!(
                "iona_ics020_total_escrow",
                "Total amount in escrow"
            )?,
            in_flight_packets: register_gauge!(
                "iona_ics020_in_flight_packets",
                "Number of in-flight packets"
            )?,
            voucher_total: register_gauge!(
                "iona_ics020_voucher_total",
                "Total voucher balance"
            )?,
            module_coherence: register_gauge!(
                "iona_ics020_module_coherence",
                "Overall module quantum coherence"
            )?,
        })
    }

    /// Create an unregistered instance (for tests or when disabled).
    pub fn new_unregistered() -> Self {
        Self {
            transfers_sent: Counter::new("iona_ics020_transfers_sent_total", "Sent").unwrap(),
            transfers_received: Counter::new("iona_ics020_transfers_received_total", "Received").unwrap(),
            transfers_timed_out: Counter::new("iona_ics020_transfers_timed_out_total", "Timed out").unwrap(),
            channels_opened: Counter::new("iona_ics020_channels_opened_total", "Opened").unwrap(),
            packets_acknowledged: Counter::new("iona_ics020_packets_acknowledged_total", "Acked").unwrap(),
            total_escrow: Gauge::new("iona_ics020_total_escrow", "Escrow").unwrap(),
            in_flight_packets: Gauge::new("iona_ics020_in_flight_packets", "In-flight").unwrap(),
            voucher_total: Gauge::new("iona_ics020_voucher_total", "Vouchers").unwrap(),
            module_coherence: Gauge::new("iona_ics020_module_coherence", "Coherence").unwrap(),
        }
    }

    pub fn record_transfer_sent(&self) {
        self.transfers_sent.inc();
    }
    pub fn record_transfer_received(&self) {
        self.transfers_received.inc();
    }
    pub fn record_transfer_timed_out(&self) {
        self.transfers_timed_out.inc();
    }
    pub fn record_channel_opened(&self) {
        self.channels_opened.inc();
    }
    pub fn record_packet_acknowledged(&self) {
        self.packets_acknowledged.inc();
    }
    pub fn set_total_escrow(&self, amount: u64) {
        self.total_escrow.set(amount as f64);
    }
    pub fn set_in_flight(&self, count: usize) {
        self.in_flight_packets.set(count as f64);
    }
    pub fn set_voucher_total(&self, amount: u64) {
        self.voucher_total.set(amount as f64);
    }
    pub fn set_coherence(&self, val: f64) {
        self.module_coherence.set(val);
    }
}

// -----------------------------------------------------------------------------
// Quantum IBC Channel Types
// -----------------------------------------------------------------------------

pub type ChannelId = String;
pub type PortId = String;
pub type Denom = String;

/// Quantum IBC channel for token transfers.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Channel {
    pub channel_id: ChannelId,
    pub port_id: PortId,
    pub counterparty_channel: ChannelId,
    pub counterparty_port: PortId,
    pub client_id: ClientId,
    pub state: ChannelState,
    pub ordering: ChannelOrdering,
    #[serde(default = "default_coherence")]
    pub coherence: f64,
    #[serde(default = "default_coherence")]
    pub entanglement_fidelity: f64,
    #[serde(default)]
    pub created_at: u64,
    #[serde(default)]
    pub last_updated: u64,
}

fn default_coherence() -> f64 {
    1.0
}

/// Channel state — quantum eigenstates.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum ChannelState {
    Init,
    TryOpen,
    Open,
    Closed,
}

/// Channel ordering — quantum statistics.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum ChannelOrdering {
    Unordered,
    Ordered,
}

// -----------------------------------------------------------------------------
// Quantum Fungible Token Packet
// -----------------------------------------------------------------------------

/// Quantum fungible token packet — the state vector for a transfer.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FungibleTokenPacket {
    pub denom: Denom,
    pub amount: String,
    pub sender: String,
    pub receiver: String,
    pub memo: String,
    #[serde(default = "default_coherence")]
    pub coherence: f64,
}

impl FungibleTokenPacket {
    /// Validate the packet contents.
    pub fn validate(&self) -> Result<(), String> {
        if self.denom.is_empty() {
            return Err("denom cannot be empty".into());
        }
        if self.sender.is_empty() {
            return Err("sender cannot be empty".into());
        }
        if self.receiver.is_empty() {
            return Err("receiver cannot be empty".into());
        }
        // Amount must be a valid positive integer
        let amount = self.amount.parse::<u64>().map_err(|_| "amount must be a valid u64".to_string())?;
        if amount == 0 {
            return Err("amount must be > 0".into());
        }
        if self.coherence < 0.0 || self.coherence > 1.0 {
            return Err("coherence must be between 0.0 and 1.0".into());
        }
        Ok(())
    }

    /// Get the amount as u64.
    pub fn amount_u64(&self) -> Result<u64, String> {
        self.amount.parse().map_err(|_| "invalid amount".into())
    }

    /// Create a new packet with default coherence.
    pub fn new(
        denom: Denom,
        amount: u64,
        sender: String,
        receiver: String,
        memo: String,
    ) -> Self {
        Self {
            denom,
            amount: amount.to_string(),
            sender,
            receiver,
            memo,
            coherence: 1.0,
        }
    }
}

/// A quantum IBC packet with sequence, routing, and timeout.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Packet {
    pub sequence: u64,
    pub source_port: PortId,
    pub source_channel: ChannelId,
    pub destination_port: PortId,
    pub destination_channel: ChannelId,
    pub data: FungibleTokenPacket,
    pub timeout_height: Option<IbcHeight>,
    pub timeout_timestamp: u64,
    #[serde(default = "default_coherence")]
    pub fidelity: f64,
    #[serde(default)]
    pub sent_at: u64,
}

impl Packet {
    /// Validate the packet.
    pub fn validate(&self) -> Result<(), String> {
        if self.source_port.is_empty() {
            return Err("source_port cannot be empty".into());
        }
        if self.source_channel.is_empty() {
            return Err("source_channel cannot be empty".into());
        }
        if self.destination_port.is_empty() {
            return Err("destination_port cannot be empty".into());
        }
        if self.destination_channel.is_empty() {
            return Err("destination_channel cannot be empty".into());
        }
        self.data.validate()?;
        if self.fidelity < 0.0 || self.fidelity > 1.0 {
            return Err("fidelity must be between 0.0 and 1.0".into());
        }
        Ok(())
    }

    /// Check if the packet is expired at the given height and time.
    pub fn is_expired(&self, current_height: Height, current_time_s: u64) -> bool {
        if let Some(timeout_height) = self.timeout_height {
            if current_height >= timeout_height.revision_height {
                return true;
            }
        }
        if self.timeout_timestamp > 0 && current_time_s > self.timeout_timestamp {
            return true;
        }
        false
    }
}

// -----------------------------------------------------------------------------
// Quantum ICS-020 Errors
// -----------------------------------------------------------------------------

#[derive(Debug, Error)]
pub enum Ics020Error {
    #[error("channel not found: {0}")]
    ChannelNotFound(ChannelId),

    #[error("channel not open (state: {0:?})")]
    ChannelNotOpen(ChannelState),

    #[error("insufficient balance: have {have}, need {need}")]
    InsufficientBalance { have: u64, need: u64 },

    #[error("packet timed out at height {timeout:?}")]
    PacketTimeout { timeout: Option<IbcHeight> },

    #[error("invalid denom: {0}")]
    InvalidDenom(String),

    #[error("packet not found: seq={0}")]
    PacketNotFound(u64),

    #[error("quantum decoherence: fidelity {fidelity} below threshold {threshold}")]
    Decoherence { fidelity: f64, threshold: f64 },

    #[error("entanglement broken: transfer cannot be completed")]
    EntanglementBroken,

    #[error("configuration error: {0}")]
    Config(String),

    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("serialization error: {0}")]
    Serialization(#[from] serde_json::Error),

    #[error("lock acquisition failed: {0}")]
    LockFailed(String),

    #[error("invalid packet: {0}")]
    InvalidPacket(String),

    #[error("packet already acknowledged: seq={0}")]
    PacketAlreadyAcknowledged(u64),

    #[error("denom not found in escrow: {0}")]
    DenomNotFoundInEscrow(String),

    #[error("voucher not found for denom {denom} and address {address}")]
    VoucherNotFound { denom: String, address: String },

    #[error("invalid channel state transition from {from:?} to {to:?}")]
    InvalidStateTransition { from: ChannelState, to: ChannelState },

    #[error("integer overflow")]
    IntegerOverflow,
}

pub type Ics020Result<T> = Result<T, Ics020Error>;

// -----------------------------------------------------------------------------
// Persistent State (versioned)
// -----------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
struct PersistentStateV1 {
    version: u32,
    channels: BTreeMap<ChannelId, Channel>,
    escrow: BTreeMap<Denom, u64>,
    escrow_coherence: BTreeMap<Denom, f64>,
    in_flight: BTreeMap<u64, Packet>,
    send_sequence: u64,
    vouchers: Vec<(Denom, String, u64)>,
    voucher_coherence: BTreeMap<Denom, f64>,
    next_channel_seq: u64,
    coherence: f64,
    last_modified: u64,
}

impl PersistentStateV1 {
    fn from_state(state: &Ics020State) -> Self {
        let mut vouchers = Vec::new();
        for ((denom, addr), amount) in &state.vouchers {
            vouchers.push((denom.clone(), addr.clone(), *amount));
        }
        Self {
            version: CURRENT_VERSION,
            channels: state.channels.clone(),
            escrow: state.escrow.clone(),
            escrow_coherence: state.escrow_coherence.clone(),
            in_flight: state.in_flight.clone(),
            send_sequence: state.send_sequence,
            vouchers,
            voucher_coherence: state.voucher_coherence.clone(),
            next_channel_seq: state.next_channel_seq,
            coherence: state.coherence,
            last_modified: current_timestamp(),
        }
    }

    fn into_state(self) -> Ics020State {
        let mut vouchers = HashMap::new();
        for (denom, addr, amount) in self.vouchers {
            vouchers.insert((denom, addr), amount);
        }
        Ics020State {
            channels: self.channels,
            escrow: self.escrow,
            escrow_coherence: self.escrow_coherence,
            in_flight: self.in_flight,
            send_sequence: self.send_sequence,
            vouchers,
            voucher_coherence: self.voucher_coherence,
            next_channel_seq: self.next_channel_seq,
            coherence: self.coherence,
        }
    }
}

fn current_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

// -----------------------------------------------------------------------------
// File I/O with locking
// -----------------------------------------------------------------------------

fn acquire_lock(path: &Path, timeout_secs: u64) -> Result<File, Ics020Error> {
    let lock_path = path.with_extension("lock");
    let file = OpenOptions::new()
        .create(true)
        .write(true)
        .open(&lock_path)
        .map_err(|e| Ics020Error::LockFailed(e.to_string()))?;
    let timeout = Duration::from_secs(timeout_secs);
    let start = Instant::now();
    loop {
        match file.try_lock_exclusive() {
            Ok(()) => return Ok(file),
            Err(_) => {
                if start.elapsed() > timeout {
                    return Err(Ics020Error::LockFailed(format!(
                        "timeout after {}s",
                        timeout_secs
                    )));
                }
                std::thread::sleep(Duration::from_millis(100));
            }
        }
    }
}

fn load_state(path: &Path, config: &Ics020Config) -> Result<Ics020State, Ics020Error> {
    if !path.exists() {
        return Ok(Ics020State::default());
    }
    let _lock = acquire_lock(path, config.lock_timeout_secs)?;
    let file = File::open(path)?;
    let reader = BufReader::new(file);
    let raw: serde_json::Value = serde_json::from_reader(reader)?;
    if let Some(version) = raw.get("version").and_then(|v| v.as_u64()) {
        if version != CURRENT_VERSION as u64 {
            return Err(Ics020Error::Config(format!(
                "unsupported version: {} (expected {})",
                version, CURRENT_VERSION
            )));
        }
        let st: PersistentStateV1 = serde_json::from_value(raw)?;
        Ok(st.into_state())
    } else {
        // Legacy format
        match serde_json::from_value::<Ics020State>(raw) {
            Ok(state) => Ok(state),
            Err(e) => Err(Ics020Error::Serialization(e)),
        }
    }
}

fn save_state(path: &Path, state: &Ics020State, config: &Ics020Config) -> Result<(), Ics020Error> {
    let st = PersistentStateV1::from_state(state);
    let json = serde_json::to_string_pretty(&st)?;
    let _lock = acquire_lock(path, config.lock_timeout_secs)?;
    let temp_path = path.with_extension(TEMP_EXT);
    fs::write(&temp_path, &json)?;
    fs::rename(&temp_path, path)?;
    Ok(())
}

// -----------------------------------------------------------------------------
// ICS-020 State
// -----------------------------------------------------------------------------

/// Quantum ICS-020 transfer module state.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Ics020State {
    pub channels: BTreeMap<ChannelId, Channel>,
    pub escrow: BTreeMap<Denom, u64>,
    pub escrow_coherence: BTreeMap<Denom, f64>,
    pub in_flight: BTreeMap<u64, Packet>,
    pub send_sequence: u64,
    pub vouchers: HashMap<(Denom, String), u64>,
    pub voucher_coherence: BTreeMap<Denom, f64>,
    pub next_channel_seq: u64,
    pub coherence: f64,
}

impl Ics020State {
    /// Open a new quantum transfer channel.
    pub fn open_channel(
        &mut self,
        port_id: PortId,
        counterparty_channel: ChannelId,
        counterparty_port: PortId,
        client_id: ClientId,
        ordering: ChannelOrdering,
    ) -> Result<ChannelId, Ics020Error> {
        let channel_id = format!("channel-{}", self.next_channel_seq);
        self.next_channel_seq = self
            .next_channel_seq
            .checked_add(1)
            .ok_or(Ics020Error::IntegerOverflow)?;

        self.channels.insert(
            channel_id.clone(),
            Channel {
                channel_id: channel_id.clone(),
                port_id,
                counterparty_channel,
                counterparty_port,
                client_id,
                state: ChannelState::Open,
                ordering,
                coherence: 1.0,
                entanglement_fidelity: 1.0,
                created_at: current_timestamp(),
                last_updated: current_timestamp(),
            },
        );

        self.coherence = (self.coherence * 0.9999).clamp(0.0, 1.0);
        Ok(channel_id)
    }

    /// Send tokens via quantum IBC.
    pub fn send_transfer(
        &mut self,
        channel_id: &str,
        sender: String,
        receiver: String,
        denom: Denom,
        amount: u64,
        sender_balances: &mut BTreeMap<String, u64>,
        timeout_height: Option<IbcHeight>,
        timeout_timestamp: u64,
        config: &Ics020Config,
    ) -> Result<u64, Ics020Error> {
        let channel = self
            .channels
            .get(channel_id)
            .ok_or_else(|| Ics020Error::ChannelNotFound(channel_id.to_string()))?
            .clone();

        if channel.state != ChannelState::Open {
            return Err(Ics020Error::ChannelNotOpen(channel.state));
        }

        if amount == 0 {
            return Err(Ics020Error::InvalidPacket("amount must be > 0".into()));
        }

        let bal = sender_balances.get(&sender).copied().unwrap_or(0);
        if bal < amount {
            return Err(Ics020Error::InsufficientBalance {
                have: bal,
                need: amount,
            });
        }

        // Lock tokens in escrow
        let new_bal = bal.checked_sub(amount).ok_or(Ics020Error::IntegerOverflow)?;
        sender_balances.insert(sender.clone(), new_bal);

        let escrow_entry = self.escrow.entry(denom.clone()).or_insert(0);
        *escrow_entry = escrow_entry.checked_add(amount).ok_or(Ics020Error::IntegerOverflow)?;

        let esc_coh = self.escrow_coherence.entry(denom.clone()).or_insert(1.0);
        *esc_coh = (*esc_coh * (1.0 - config.decoherence_rate)).clamp(0.0, 1.0);

        let seq = self.send_sequence;
        self.send_sequence = self
            .send_sequence
            .checked_add(1)
            .ok_or(Ics020Error::IntegerOverflow)?;

        let packet = Packet {
            sequence: seq,
            source_port: channel.port_id.clone(),
            source_channel: channel_id.to_string(),
            destination_port: channel.counterparty_port.clone(),
            destination_channel: channel.counterparty_channel.clone(),
            data: FungibleTokenPacket::new(denom.clone(), amount, sender, receiver, String::new()),
            timeout_height,
            timeout_timestamp,
            fidelity: config.min_packet_fidelity,
            sent_at: current_timestamp(),
        };

        self.in_flight.insert(seq, packet);
        self.coherence = (self.coherence * (1.0 - config.decoherence_rate)).clamp(0.0, 1.0);

        info!(
            channel = %channel_id,
            denom = %denom,
            amount = amount,
            seq = seq,
            "transfer sent"
        );

        Ok(seq)
    }

    /// Receive a packet from a remote chain.
    pub fn receive_packet(
        &mut self,
        packet: &FungibleTokenPacket,
        receiver_balances: &mut BTreeMap<String, u64>,
        config: &Ics020Config,
    ) -> Result<(), Ics020Error> {
        packet.validate().map_err(Ics020Error::InvalidPacket)?;

        if packet.coherence < config.min_packet_fidelity {
            return Err(Ics020Error::Decoherence {
                fidelity: packet.coherence,
                threshold: config.min_packet_fidelity,
            });
        }

        let amount = packet.amount_u64().map_err(Ics020Error::InvalidPacket)?;
        let is_native_return = packet.denom.starts_with("transfer/");

        if is_native_return {
            let native_denom = packet
                .denom
                .split('/')
                .last()
                .unwrap_or(&packet.denom)
                .to_string();

            let escrowed = self.escrow.get(&native_denom).copied().unwrap_or(0);
            if escrowed < amount {
                return Err(Ics020Error::InsufficientBalance {
                    have: escrowed,
                    need: amount,
                });
            }

            let new_escrow = escrowed.checked_sub(amount).ok_or(Ics020Error::IntegerOverflow)?;
            self.escrow.insert(native_denom.clone(), new_escrow);

            let receiver_bal = receiver_balances.entry(packet.receiver.clone()).or_insert(0);
            *receiver_bal = receiver_bal.checked_add(amount).ok_or(Ics020Error::IntegerOverflow)?;

            if let Some(coh) = self.escrow_coherence.get_mut(&native_denom) {
                *coh = (*coh * 0.999).clamp(0.0, 1.0);
            }

            info!(
                receiver = %packet.receiver,
                denom = %native_denom,
                amount = amount,
                "native return: escrow unlocked"
            );
        } else {
            let voucher_denom = format!("transfer/{}", packet.denom);
            let key = (voucher_denom.clone(), packet.receiver.clone());

            let voucher_entry = self.vouchers.entry(key).or_insert(0);
            *voucher_entry = voucher_entry.checked_add(amount).ok_or(Ics020Error::IntegerOverflow)?;

            let v_coh = self.voucher_coherence.entry(voucher_denom.clone()).or_insert(1.0);
            *v_coh = (*v_coh * 0.999).clamp(0.0, 1.0);

            info!(
                receiver = %packet.receiver,
                denom = %voucher_denom,
                amount = amount,
                "voucher minted"
            );
        }

        self.coherence = (self.coherence * 0.9999).clamp(0.0, 1.0);
        Ok(())
    }

    /// Handle packet timeout.
    pub fn timeout_packet(
        &mut self,
        seq: u64,
        sender_balances: &mut BTreeMap<String, u64>,
        config: &Ics020Config,
    ) -> Result<(), Ics020Error> {
        let packet = self
            .in_flight
            .remove(&seq)
            .ok_or(Ics020Error::PacketNotFound(seq))?;

        let amount = packet.data.amount_u64().map_err(Ics020Error::InvalidPacket)?;
        let denom = packet.data.denom.clone();
        let sender = packet.data.sender.clone();

        let escrowed = self.escrow.get(&denom).copied().unwrap_or(0);
        if escrowed < amount {
            return Err(Ics020Error::InsufficientBalance {
                have: escrowed,
                need: amount,
            });
        }

        let new_escrow = escrowed.checked_sub(amount).ok_or(Ics020Error::IntegerOverflow)?;
        self.escrow.insert(denom.clone(), new_escrow);

        let sender_bal = sender_balances.entry(sender.clone()).or_insert(0);
        *sender_bal = sender_bal.checked_add(amount).ok_or(Ics020Error::IntegerOverflow)?;

        if let Some(coh) = self.escrow_coherence.get_mut(&denom) {
            *coh = (*coh * (1.0 - config.decoherence_rate * 2.0)).clamp(0.0, 1.0);
        }

        self.coherence = (self.coherence * (1.0 - config.decoherence_rate)).clamp(0.0, 1.0);

        warn!(
            seq = seq,
            sender = %sender,
            amount = amount,
            "packet timed out — refunded"
        );

        Ok(())
    }

    /// Acknowledge a packet (remove from in-flight).
    pub fn acknowledge_packet(&mut self, seq: u64) -> Result<(), Ics020Error> {
        if self.in_flight.remove(&seq).is_some() {
            debug!(seq = seq, "packet acknowledged");
            Ok(())
        } else {
            Err(Ics020Error::PacketNotFound(seq))
        }
    }

    /// Query voucher balance.
    pub fn voucher_balance(&self, denom_path: &str, addr: &str) -> u64 {
        self.vouchers
            .get(&(denom_path.to_string(), addr.to_string()))
            .copied()
            .unwrap_or(0)
    }

    /// Get escrow coherence.
    pub fn escrow_coherence_for(&self, denom: &str) -> f64 {
        self.escrow_coherence.get(denom).copied().unwrap_or(1.0)
    }

    /// Get voucher coherence.
    pub fn voucher_coherence_for(&self, denom: &str) -> f64 {
        self.voucher_coherence.get(denom).copied().unwrap_or(1.0)
    }

    /// Get statistics.
    pub fn stats(&self) -> Ics020Stats {
        Ics020Stats {
            total_channels: self.channels.len(),
            open_channels: self.channels.values().filter(|c| c.state == ChannelState::Open).count(),
            total_escrow: self.escrow.values().sum(),
            in_flight_packets: self.in_flight.len(),
            total_vouchers: self.vouchers.values().sum(),
            coherence: self.coherence,
        }
    }

    /// Prune expired packets.
    pub fn prune_expired(&mut self, current_height: Height, current_time_s: u64) -> usize {
        let expired: Vec<u64> = self
            .in_flight
            .iter()
            .filter(|(_, p)| p.is_expired(current_height, current_time_s))
            .map(|(seq, _)| *seq)
            .collect();

        let count = expired.len();
        for seq in expired {
            self.in_flight.remove(&seq);
            debug!(seq = seq, "removed expired packet");
        }
        count
    }
}

// -----------------------------------------------------------------------------
// Statistics
// -----------------------------------------------------------------------------

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
// ICS-020 Manager (thread‑safe, persistent)
// -----------------------------------------------------------------------------

#[derive(Clone)]
pub struct Ics020Manager {
    state: Arc<Mutex<Ics020State>>,
    config: Arc<Ics020Config>,
    path: Option<PathBuf>,
    balances: Arc<Mutex<BTreeMap<String, u64>>>,
    metrics: Arc<Ics020Metrics>,
}

impl Ics020Manager {
    /// Create a new manager with configuration.
    pub fn new(config: Ics020Config) -> Result<Self, Ics020Error> {
        config.validate().map_err(Ics020Error::Config)?;
        let metrics = if config.enable_metrics {
            Arc::new(Ics020Metrics::new().map_err(|e| Ics020Error::Config(e.to_string()))?)
        } else {
            Arc::new(Ics020Metrics::new_unregistered())
        };
        Ok(Self {
            state: Arc::new(Mutex::new(Ics020State::default())),
            config: Arc::new(config),
            path: None,
            balances: Arc::new(Mutex::new(BTreeMap::new())),
            metrics,
        })
    }

    /// Create a manager with persistence.
    pub fn with_persistence(data_dir: &str, config: Ics020Config) -> Result<Self, Ics020Error> {
        config.validate().map_err(Ics020Error::Config)?;
        let metrics = if config.enable_metrics {
            Arc::new(Ics020Metrics::new().map_err(|e| Ics020Error::Config(e.to_string()))?)
        } else {
            Arc::new(Ics020Metrics::new_unregistered())
        };
        let path = PathBuf::from(data_dir).join("ics020_state.json");
        let state = if path.exists() {
            load_state(&path, &config)?
        } else {
            Ics020State::default()
        };
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        let manager = Self {
            state: Arc::new(Mutex::new(state)),
            config: Arc::new(config),
            path: Some(path.clone()),
            balances: Arc::new(Mutex::new(BTreeMap::new())),
            metrics,
        };
        if manager.config.persist_state {
            let st = manager.state.lock();
            let _ = save_state(&path, &st, &manager.config);
        }
        manager.update_metrics();
        Ok(manager)
    }

    /// Open a channel.
    pub fn open_channel(
        &self,
        port_id: PortId,
        counterparty_channel: ChannelId,
        counterparty_port: PortId,
        client_id: ClientId,
        ordering: ChannelOrdering,
    ) -> Ics020Result<ChannelId> {
        let mut state = self.state.lock();
        let id = state.open_channel(port_id, counterparty_channel, counterparty_port, client_id, ordering)?;
        self.metrics.record_channel_opened();
        self.update_metrics();
        if self.config.persist_state {
            if let Some(path) = &self.path {
                let _ = save_state(path, &state, &self.config);
            }
        }
        Ok(id)
    }

    /// Send a transfer.
    pub fn send_transfer(
        &self,
        channel_id: &str,
        sender: String,
        receiver: String,
        denom: Denom,
        amount: u64,
        timeout_height: Option<IbcHeight>,
        timeout_timestamp: u64,
    ) -> Ics020Result<u64> {
        let mut state = self.state.lock();
        let mut balances = self.balances.lock();
        let seq = state.send_transfer(
            channel_id,
            sender,
            receiver,
            denom,
            amount,
            &mut balances,
            timeout_height,
            timeout_timestamp,
            &self.config,
        )?;
        self.metrics.record_transfer_sent();
        self.update_metrics();
        if self.config.persist_state {
            if let Some(path) = &self.path {
                let _ = save_state(path, &state, &self.config);
            }
        }
        Ok(seq)
    }

    /// Receive a packet.
    pub fn receive_packet(
        &self,
        packet: &FungibleTokenPacket,
    ) -> Ics020Result<()> {
        let mut state = self.state.lock();
        let mut balances = self.balances.lock();
        state.receive_packet(packet, &mut balances, &self.config)?;
        self.metrics.record_transfer_received();
        self.update_metrics();
        if self.config.persist_state {
            if let Some(path) = &self.path {
                let _ = save_state(path, &state, &self.config);
            }
        }
        Ok(())
    }

    /// Timeout a packet.
    pub fn timeout_packet(&self, seq: u64) -> Ics020Result<()> {
        let mut state = self.state.lock();
        let mut balances = self.balances.lock();
        state.timeout_packet(seq, &mut balances, &self.config)?;
        self.metrics.record_transfer_timed_out();
        self.update_metrics();
        if self.config.persist_state {
            if let Some(path) = &self.path {
                let _ = save_state(path, &state, &self.config);
            }
        }
        Ok(())
    }

    /// Acknowledge a packet.
    pub fn acknowledge_packet(&self, seq: u64) -> Ics020Result<()> {
        let mut state = self.state.lock();
        state.acknowledge_packet(seq)?;
        self.metrics.record_packet_acknowledged();
        self.update_metrics();
        if self.config.persist_state {
            if let Some(path) = &self.path {
                let _ = save_state(path, &state, &self.config);
            }
        }
        Ok(())
    }

    /// Get voucher balance.
    pub fn voucher_balance(&self, denom_path: &str, addr: &str) -> u64 {
        self.state.lock().voucher_balance(denom_path, addr)
    }

    /// Get stats.
    pub fn stats(&self) -> Ics020Stats {
        self.state.lock().stats()
    }

    /// Prune expired packets.
    pub fn prune_expired(&self, current_height: Height, current_time_s: u64) -> usize {
        let mut state = self.state.lock();
        let count = state.prune_expired(current_height, current_time_s);
        if self.config.persist_state && count > 0 {
            if let Some(path) = &self.path {
                let _ = save_state(path, &state, &self.config);
            }
        }
        count
    }

    /// Flush state to disk.
    pub fn flush(&self) -> Ics020Result<()> {
        if let Some(path) = &self.path {
            let state = self.state.lock();
            save_state(path, &state, &self.config)?;
        }
        Ok(())
    }

    /// Get configuration.
    pub fn config(&self) -> &Ics020Config {
        &self.config
    }

    /// Get a channel by ID.
    pub fn channel(&self, id: &str) -> Option<Channel> {
        self.state.lock().channels.get(id).cloned()
    }

    /// List all channel IDs.
    pub fn channel_ids(&self) -> Vec<ChannelId> {
        self.state.lock().channels.keys().cloned().collect()
    }

    /// Get in-flight packet by sequence.
    pub fn in_flight_packet(&self, seq: u64) -> Option<Packet> {
        self.state.lock().in_flight.get(&seq).cloned()
    }

    /// List all in-flight packet sequences.
    pub fn in_flight_seqs(&self) -> Vec<u64> {
        self.state.lock().in_flight.keys().copied().collect()
    }

    /// Get all escrow amounts.
    pub fn escrow_balances(&self) -> BTreeMap<Denom, u64> {
        self.state.lock().escrow.clone()
    }

    /// Set a balance (for testing).
    #[cfg(test)]
    pub fn set_balance(&self, addr: &str, amount: u64) {
        let mut balances = self.balances.lock();
        balances.insert(addr.to_string(), amount);
    }

    /// Get a balance.
    pub fn balance(&self, addr: &str) -> u64 {
        self.balances.lock().get(addr).copied().unwrap_or(0)
    }

    /// Update metrics from current state.
    fn update_metrics(&self) {
        let state = self.state.lock();
        self.metrics.set_total_escrow(state.escrow.values().sum());
        self.metrics.set_in_flight(state.in_flight.len());
        self.metrics.set_voucher_total(state.vouchers.values().sum());
        self.metrics.set_coherence(state.coherence);
    }

    /// Get a snapshot of metrics (for testing or external monitoring).
    pub fn metrics_snapshot(&self) -> Ics020MetricsSnapshot {
        Ics020MetricsSnapshot {
            transfers_sent: self.metrics.transfers_sent.get(),
            transfers_received: self.metrics.transfers_received.get(),
            transfers_timed_out: self.metrics.transfers_timed_out.get(),
            channels_opened: self.metrics.channels_opened.get(),
            packets_acknowledged: self.metrics.packets_acknowledged.get(),
            total_escrow: self.metrics.total_escrow.get() as u64,
            in_flight_packets: self.metrics.in_flight_packets.get() as usize,
            voucher_total: self.metrics.voucher_total.get() as u64,
            module_coherence: self.metrics.module_coherence.get(),
        }
    }
}

/// Snapshot of metrics for external use.
#[derive(Debug, Clone)]
pub struct Ics020MetricsSnapshot {
    pub transfers_sent: u64,
    pub transfers_received: u64,
    pub transfers_timed_out: u64,
    pub channels_opened: u64,
    pub packets_acknowledged: u64,
    pub total_escrow: u64,
    pub in_flight_packets: usize,
    pub voucher_total: u64,
    pub module_coherence: f64,
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    fn test_config() -> Ics020Config {
        let mut cfg = Ics020Config::default();
        cfg.persist_state = true;
        cfg.enable_metrics = false; // avoid global registration conflicts
        cfg.min_packet_fidelity = 0.5;
        cfg
    }

    #[test]
    fn test_send_and_receive_roundtrip() {
        let cfg = test_config();
        let manager = Ics020Manager::new(cfg).unwrap();
        manager.set_balance("alice", 1_000_000);

        let ch = manager.open_channel(
            "transfer".into(),
            "channel-42".into(),
            "transfer".into(),
            "client-0".into(),
            ChannelOrdering::Unordered,
        ).unwrap();

        let seq = manager
            .send_transfer(
                &ch,
                "alice".into(),
                "cosmos1abc".into(),
                "uiona".into(),
                500_000,
                None,
                0,
            )
            .unwrap();

        assert_eq!(manager.balance("alice"), 500_000);
        let stats = manager.stats();
        assert_eq!(stats.total_escrow, 500_000);
        assert_eq!(stats.in_flight_packets, 1);

        let return_packet = FungibleTokenPacket::new(
            "transfer/uiona".into(),
            500_000,
            "cosmos1abc".into(),
            "alice".into(),
            String::new(),
        );
        manager.receive_packet(&return_packet).unwrap();
        assert_eq!(manager.balance("alice"), 1_000_000);
    }

    #[test]
    fn test_timeout_refunds_sender() {
        let cfg = test_config();
        let manager = Ics020Manager::new(cfg).unwrap();
        manager.set_balance("bob", 1_000_000);

        let ch = manager.open_channel(
            "transfer".into(),
            "ch-1".into(),
            "transfer".into(),
            "client-0".into(),
            ChannelOrdering::Unordered,
        ).unwrap();

        let seq = manager
            .send_transfer(
                &ch,
                "bob".into(),
                "cosmos1xyz".into(),
                "uiona".into(),
                300_000,
                None,
                0,
            )
            .unwrap();

        manager.timeout_packet(seq).unwrap();
        assert_eq!(manager.balance("bob"), 1_000_000);
    }

    #[test]
    fn test_voucher_balance() {
        let cfg = test_config();
        let manager = Ics020Manager::new(cfg).unwrap();

        let packet = FungibleTokenPacket::new(
            "uatom".into(),
            500,
            "chain1".into(),
            "alice".into(),
            String::new(),
        );
        manager.receive_packet(&packet).unwrap();

        assert_eq!(manager.voucher_balance("transfer/uatom", "alice"), 500);
    }

    #[test]
    fn test_stats() {
        let cfg = test_config();
        let manager = Ics020Manager::new(cfg).unwrap();

        manager.open_channel(
            "transfer".into(),
            "ch-1".into(),
            "transfer".into(),
            "client-0".into(),
            ChannelOrdering::Unordered,
        ).unwrap();

        let stats = manager.stats();
        assert_eq!(stats.total_channels, 1);
        assert_eq!(stats.open_channels, 1);
        assert!(stats.coherence > 0.99);
    }

    #[test]
    fn test_persistence() {
        let dir = tempdir().unwrap();
        let path = dir.path().to_str().unwrap();
        let cfg = test_config();

        {
            let manager = Ics020Manager::with_persistence(path, cfg.clone()).unwrap();
            manager.set_balance("alice", 1_000_000);
            let ch = manager.open_channel(
                "transfer".into(),
                "ch-p".into(),
                "transfer".into(),
                "client-p".into(),
                ChannelOrdering::Unordered,
            ).unwrap();
            manager
                .send_transfer(
                    &ch,
                    "alice".into(),
                    "receiver".into(),
                    "uiona".into(),
                    100_000,
                    None,
                    0,
                )
                .unwrap();
            manager.flush().unwrap();
        }

        {
            let manager = Ics020Manager::with_persistence(path, cfg).unwrap();
            let stats = manager.stats();
            assert_eq!(stats.total_channels, 1);
            assert_eq!(stats.total_escrow, 100_000);
            assert_eq!(stats.in_flight_packets, 1);
            assert_eq!(manager.balance("alice"), 900_000);
        }
    }

    #[test]
    fn test_pruning() {
        let cfg = test_config();
        let manager = Ics020Manager::new(cfg).unwrap();
        manager.set_balance("alice", 10_000_000);

        let ch = manager.open_channel(
            "transfer".into(),
            "ch-1".into(),
            "transfer".into(),
            "client-0".into(),
            ChannelOrdering::Unordered,
        ).unwrap();

        for i in 0..10 {
            manager
                .send_transfer(
                    &ch,
                    "alice".into(),
                    format!("receiver{}", i),
                    "uiona".into(),
                    1000,
                    Some(IbcHeight::new(1, 5 + i)),
                    0,
                )
                .unwrap();
        }

        let pruned = manager.prune_expired(10, 1000);
        assert!(pruned > 0);
    }

    #[test]
    fn test_config_validation() {
        let mut cfg = Ics020Config::default();
        assert!(cfg.validate().is_ok());

        cfg.min_packet_fidelity = 1.5;
        assert!(cfg.validate().is_err());

        cfg.min_packet_fidelity = 0.5;
        cfg.default_timeout_height_offset = 0;
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn test_packet_validation() {
        let packet = FungibleTokenPacket::new(
            "uiona".into(),
            100,
            "alice".into(),
            "bob".into(),
            String::new(),
        );
        assert!(packet.validate().is_ok());

        let mut bad = packet.clone();
        bad.denom = String::new();
        assert!(bad.validate().is_err());

        let mut bad2 = packet.clone();
        bad2.amount = "invalid".into();
        assert!(bad2.validate().is_err());
    }

    #[test]
    fn test_acknowledge_packet() {
        let cfg = test_config();
        let manager = Ics020Manager::new(cfg).unwrap();
        manager.set_balance("alice", 1_000_000);

        let ch = manager.open_channel(
            "transfer".into(),
            "ch-ack".into(),
            "transfer".into(),
            "client-ack".into(),
            ChannelOrdering::Unordered,
        ).unwrap();

        let seq = manager
            .send_transfer(
                &ch,
                "alice".into(),
                "receiver".into(),
                "uiona".into(),
                100_000,
                None,
                0,
            )
            .unwrap();

        assert_eq!(manager.stats().in_flight_packets, 1);
        manager.acknowledge_packet(seq).unwrap();
        assert_eq!(manager.stats().in_flight_packets, 0);
    }
}
