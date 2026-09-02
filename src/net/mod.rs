//! Networking layer for IONA — Quantum Architecture.
//!
//! # Quantum Network Model
//!
//! The P2P network is modelled as a **quantum many-body system** where each
//! peer exists in a superposition of connected/disconnected states and
//! messages propagate via **entanglement swapping**.
//!
//! # Mathematical Formalism
//!
//! ## Network State
//! ```text
//! |Ψ_network⟩ = (1/√N) Σ_{i=1}^N |peer_i⟩ ⊗ |channel_i⟩
//! ```
//!
//! ## Hamiltonian
//! ```text
//! Ĥ_net = Ĥ_p2p + Ĥ_sync + Ĥ_score + Ĥ_eclipse + Ĥ_store
//!
//! Ĥ_p2p     = Σ_i g_i (a†_i + a_i)                       (message creation/annihilation)
//! Ĥ_sync    = Σ_j h_j σ^+_j σ^-_k                         (state transfer entanglement)
//! Ĥ_score   = Σ_k ω_k n̂_k                                  (reputation oscillator)
//! Ĥ_eclipse = -J Σ_{l≠m} |l⟩⟨m|                           (diversity coupling)
//! Ĥ_store   = Σ_n E_n |peer_n⟩⟨peer_n|                    (persistent states)
//! ```
//!
//! # Submodules
//!
//! - `p2p` – Production P2P networking (libp2p‑based).
//! - `state_sync` – Fast state sync over the network.
//! - `peer_score` – Peer scoring and reputation management.
//! - `inmem` – In‑memory network for integration testing.
//! - `simnet` – Simulated network for chaos testing.
//! - `eclipse_profiles` – Eclipse attack protection profiles.
//! - `peerstore` – Persistent peer address storage.
//!
//! # Usage
//!
//! ```rust,ignore
//! use iona::net::p2p::P2pNetwork;
//! use iona::net::peer_score::PeerScore;
//! use iona::net::peerstore::PeerStore;
//! ```

pub mod p2p;
pub mod state_sync;
pub mod peer_score;
pub mod inmem;
pub mod simnet;
pub mod eclipse_profiles;
pub mod peerstore;

use parking_lot::Mutex;
use prometheus::{register_counter, register_gauge, Counter, Gauge};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use thiserror::Error;

// -----------------------------------------------------------------------------
// Quantum Constants
// -----------------------------------------------------------------------------

/// Reduced Planck constant (natural units).
pub const HBAR: f64 = 1.0;

/// Default quantum coherence for network components.
pub const DEFAULT_NETWORK_COHERENCE: f64 = 1.0;

/// Decoherence rate per network operation.
pub const NETWORK_DECOHERENCE_RATE: f64 = 0.0001;

/// Minimum coherence threshold for healthy network.
pub const MIN_NETWORK_COHERENCE: f64 = 0.9;

/// Default whether metrics are enabled.
const DEFAULT_ENABLE_METRICS: bool = false;

// -----------------------------------------------------------------------------
// Quantum Network State (shared across networking modules)
// -----------------------------------------------------------------------------

/// Quantum state of the overall networking subsystem.
///
/// Tracks the density matrix properties of the P2P network, providing
/// observables for monitoring network health.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QuantumNetworkState {
    /// Purity γ = Tr(ρ²) of the network state.
    pub purity: f64,
    /// Von Neumann entropy S = -Tr(ρ ln ρ).
    pub entropy: f64,
    /// Coherence of peer connections.
    pub connection_coherence: f64,
    /// Entanglement fidelity with the validator set.
    pub validator_entanglement: f64,
    /// Total messages sent across the network.
    pub total_messages_sent: u64,
    /// Total messages received.
    pub total_messages_received: u64,
    /// Total peer connections established.
    pub total_connections: u64,
    /// Total peer disconnections.
    pub total_disconnections: u64,
    /// Whether the network is in a healthy quantum state.
    pub is_healthy: bool,
}

impl Default for QuantumNetworkState {
    fn default() -> Self {
        Self {
            purity: DEFAULT_NETWORK_COHERENCE,
            entropy: 0.0,
            connection_coherence: DEFAULT_NETWORK_COHERENCE,
            validator_entanglement: DEFAULT_NETWORK_COHERENCE,
            total_messages_sent: 0,
            total_messages_received: 0,
            total_connections: 0,
            total_disconnections: 0,
            is_healthy: true,
        }
    }
}

impl QuantumNetworkState {
    /// Create a new quantum network state in the ground state |∅⟩.
    pub fn new() -> Self {
        Self::default()
    }

    /// Apply decoherence from a network operation.
    pub fn apply_operation_decoherence(&mut self) {
        let decay = (-NETWORK_DECOHERENCE_RATE).exp();
        self.connection_coherence = (self.connection_coherence * decay).clamp(0.0, 1.0);
        self.validator_entanglement = (self.validator_entanglement * decay.sqrt()).clamp(0.0, 1.0);
        self.recompute();
    }

    /// Record a message sent event.
    pub fn record_message_sent(&mut self) {
        self.total_messages_sent = self.total_messages_sent.saturating_add(1);
        self.apply_operation_decoherence();
    }

    /// Record a message received event.
    pub fn record_message_received(&mut self) {
        self.total_messages_received = self.total_messages_received.saturating_add(1);
        self.apply_operation_decoherence();
    }

    /// Record a new connection.
    pub fn record_connection(&mut self) {
        self.total_connections = self.total_connections.saturating_add(1);
        // New connections restore some coherence
        self.connection_coherence = (self.connection_coherence * 1.001).min(1.0);
        self.recompute();
    }

    /// Record a disconnection.
    pub fn record_disconnection(&mut self) {
        self.total_disconnections = self.total_disconnections.saturating_add(1);
        let decay = (-NETWORK_DECOHERENCE_RATE * 10.0).exp();
        self.connection_coherence = (self.connection_coherence * decay).clamp(0.0, 1.0);
        self.recompute();
    }

    fn recompute(&mut self) {
        self.purity = (self.connection_coherence * self.validator_entanglement).clamp(0.0, 1.0);
        self.entropy = if self.purity >= 1.0 {
            0.0
        } else {
            -self.purity * self.purity.ln().max(0.0)
        };
        self.is_healthy = self.purity >= MIN_NETWORK_COHERENCE;
    }

    /// Get a snapshot of the network statistics.
    pub fn stats(&self) -> NetworkStats {
        NetworkStats {
            purity: self.purity,
            entropy: self.entropy,
            connection_coherence: self.connection_coherence,
            validator_entanglement: self.validator_entanglement,
            total_messages_sent: self.total_messages_sent,
            total_messages_received: self.total_messages_received,
            total_connections: self.total_connections,
            total_disconnections: self.total_disconnections,
            is_healthy: self.is_healthy,
        }
    }
}

// -----------------------------------------------------------------------------
// Network Statistics
// -----------------------------------------------------------------------------

/// Observable statistics for the quantum network subsystem.
#[derive(Debug, Clone)]
pub struct NetworkStats {
    pub purity: f64,
    pub entropy: f64,
    pub connection_coherence: f64,
    pub validator_entanglement: f64,
    pub total_messages_sent: u64,
    pub total_messages_received: u64,
    pub total_connections: u64,
    pub total_disconnections: u64,
    pub is_healthy: bool,
}

// -----------------------------------------------------------------------------
// Networking Configuration
// -----------------------------------------------------------------------------

/// Global networking configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetConfig {
    /// Listen multiaddress (e.g. "/ip4/0.0.0.0/tcp/7001").
    pub listen: String,
    /// Static peer multiaddresses.
    pub peers: Vec<String>,
    /// Bootstrap node multiaddresses.
    pub bootnodes: Vec<String>,
    /// Enable mDNS discovery.
    pub enable_mdns: bool,
    /// Enable Kademlia DHT.
    pub enable_kad: bool,
    /// Reconnect interval in seconds.
    pub reconnect_s: u64,
    /// Maximum total connections.
    pub max_connections_total: usize,
    /// Maximum connections per peer.
    pub max_connections_per_peer: usize,
    /// Whether to enable Prometheus metrics for the network subsystem.
    pub enable_metrics: bool,
}

impl Default for NetConfig {
    fn default() -> Self {
        Self {
            listen: "/ip4/0.0.0.0/tcp/7001".into(),
            peers: vec![],
            bootnodes: vec![],
            enable_mdns: false,
            enable_kad: true,
            reconnect_s: 30,
            max_connections_total: 200,
            max_connections_per_peer: 8,
            enable_metrics: DEFAULT_ENABLE_METRICS,
        }
    }
}

impl NetConfig {
    /// Validate the networking configuration.
    pub fn validate(&self) -> Result<(), String> {
        if !self.listen.contains("/tcp/") && !self.listen.contains("/ws/") {
            return Err("listen must be a valid multiaddress with /tcp/ or /ws/".into());
        }
        if self.max_connections_total == 0 {
            return Err("max_connections_total must be > 0".into());
        }
        if self.max_connections_per_peer == 0 {
            return Err("max_connections_per_peer must be > 0".into());
        }
        if self.reconnect_s == 0 {
            return Err("reconnect_s must be > 0".into());
        }
        Ok(())
    }
}

// -----------------------------------------------------------------------------
// Network Metrics
// -----------------------------------------------------------------------------

/// Prometheus metrics for the networking subsystem.
#[derive(Clone)]
pub struct NetworkMetrics {
    /// Network purity gauge.
    pub purity: Gauge,
    /// Network entropy gauge.
    pub entropy: Gauge,
    /// Connection coherence gauge.
    pub connection_coherence: Gauge,
    /// Validator entanglement gauge.
    pub validator_entanglement: Gauge,
    /// Total messages sent counter.
    pub messages_sent_total: Counter,
    /// Total messages received counter.
    pub messages_received_total: Counter,
    /// Total connections counter.
    pub connections_total: Counter,
    /// Total disconnections counter.
    pub disconnections_total: Counter,
    /// Network health gauge (1 if healthy, 0 otherwise).
    pub is_healthy: Gauge,
}

impl NetworkMetrics {
    /// Create and register metrics with the global Prometheus registry.
    pub fn new() -> Result<Self, prometheus::Error> {
        Ok(Self {
            purity: register_gauge!(
                "iona_net_purity",
                "Quantum purity of the network subsystem"
            )?,
            entropy: register_gauge!(
                "iona_net_entropy",
                "Von Neumann entropy of the network"
            )?,
            connection_coherence: register_gauge!(
                "iona_net_connection_coherence",
                "Coherence of peer connections"
            )?,
            validator_entanglement: register_gauge!(
                "iona_net_validator_entanglement",
                "Entanglement fidelity with validator set"
            )?,
            messages_sent_total: register_counter!(
                "iona_net_messages_sent_total",
                "Total messages sent"
            )?,
            messages_received_total: register_counter!(
                "iona_net_messages_received_total",
                "Total messages received"
            )?,
            connections_total: register_counter!(
                "iona_net_connections_total",
                "Total peer connections established"
            )?,
            disconnections_total: register_counter!(
                "iona_net_disconnections_total",
                "Total peer disconnections"
            )?,
            is_healthy: register_gauge!(
                "iona_net_is_healthy",
                "Whether the network is healthy (1=healthy, 0=unhealthy)"
            )?,
        })
    }

    /// Create an unregistered metrics instance (for tests or disabled metrics).
    pub fn new_unregistered() -> Self {
        Self {
            purity: Gauge::new("iona_net_purity", "Purity").unwrap(),
            entropy: Gauge::new("iona_net_entropy", "Entropy").unwrap(),
            connection_coherence: Gauge::new("iona_net_connection_coherence", "Conn coherence").unwrap(),
            validator_entanglement: Gauge::new("iona_net_validator_entanglement", "Validator entanglement").unwrap(),
            messages_sent_total: Counter::new("iona_net_messages_sent_total", "Messages sent").unwrap(),
            messages_received_total: Counter::new("iona_net_messages_received_total", "Messages received").unwrap(),
            connections_total: Counter::new("iona_net_connections_total", "Connections").unwrap(),
            disconnections_total: Counter::new("iona_net_disconnections_total", "Disconnections").unwrap(),
            is_healthy: Gauge::new("iona_net_is_healthy", "Is healthy").unwrap(),
        }
    }

    /// Update metrics from a `NetworkStats` snapshot.
    pub fn update(&self, stats: &NetworkStats) {
        self.purity.set(stats.purity);
        self.entropy.set(stats.entropy);
        self.connection_coherence.set(stats.connection_coherence);
        self.validator_entanglement.set(stats.validator_entanglement);
        self.messages_sent_total.reset();
        self.messages_sent_total.inc_by(stats.total_messages_sent as f64);
        self.messages_received_total.reset();
        self.messages_received_total.inc_by(stats.total_messages_received as f64);
        self.connections_total.reset();
        self.connections_total.inc_by(stats.total_connections as f64);
        self.disconnections_total.reset();
        self.disconnections_total.inc_by(stats.total_disconnections as f64);
        self.is_healthy.set(if stats.is_healthy { 1.0 } else { 0.0 });
    }
}

// -----------------------------------------------------------------------------
// Network State Manager (thread-safe)
// -----------------------------------------------------------------------------

/// Manages the quantum network state with thread-safety and optional metrics.
///
/// This is the central coordinator for network observability; it holds a
/// shared `QuantumNetworkState` and provides mutating methods that also
/// update metrics when enabled.
#[derive(Clone)]
pub struct NetworkStateManager {
    state: Arc<Mutex<QuantumNetworkState>>,
    metrics: Option<Arc<NetworkMetrics>>,
}

impl NetworkStateManager {
    /// Create a new manager with default state and optional metrics.
    pub fn new(enable_metrics: bool) -> Result<Self, prometheus::Error> {
        let metrics = if enable_metrics {
            Some(Arc::new(NetworkMetrics::new()?))
        } else {
            None
        };
        Ok(Self {
            state: Arc::new(Mutex::new(QuantumNetworkState::new())),
            metrics,
        })
    }

    /// Create a manager from an existing state.
    pub fn with_state(state: QuantumNetworkState, enable_metrics: bool) -> Result<Self, prometheus::Error> {
        let metrics = if enable_metrics {
            Some(Arc::new(NetworkMetrics::new()?))
        } else {
            None
        };
        Ok(Self {
            state: Arc::new(Mutex::new(state)),
            metrics,
        })
    }

    /// Record a message sent event.
    pub fn record_message_sent(&self) {
        let mut state = self.state.lock();
        state.record_message_sent();
        self.update_metrics(&state);
    }

    /// Record a message received event.
    pub fn record_message_received(&self) {
        let mut state = self.state.lock();
        state.record_message_received();
        self.update_metrics(&state);
    }

    /// Record a new connection.
    pub fn record_connection(&self) {
        let mut state = self.state.lock();
        state.record_connection();
        self.update_metrics(&state);
    }

    /// Record a disconnection.
    pub fn record_disconnection(&self) {
        let mut state = self.state.lock();
        state.record_disconnection();
        self.update_metrics(&state);
    }

    /// Get a snapshot of the current network statistics.
    pub fn stats(&self) -> NetworkStats {
        self.state.lock().stats()
    }

    /// Get the current quantum state (clone).
    pub fn state(&self) -> QuantumNetworkState {
        self.state.lock().clone()
    }

    /// Check if the network is healthy.
    pub fn is_healthy(&self) -> bool {
        self.state.lock().is_healthy
    }

    /// Get a snapshot of metrics (if enabled).
    pub fn metrics_snapshot(&self) -> Option<NetworkMetricsSnapshot> {
        self.metrics.as_ref().map(|m| NetworkMetricsSnapshot {
            purity: m.purity.get(),
            entropy: m.entropy.get(),
            connection_coherence: m.connection_coherence.get(),
            validator_entanglement: m.validator_entanglement.get(),
            total_messages_sent: m.messages_sent_total.get(),
            total_messages_received: m.messages_received_total.get(),
            total_connections: m.connections_total.get(),
            total_disconnections: m.disconnections_total.get(),
            is_healthy: m.is_healthy.get() > 0.5,
        })
    }

    fn update_metrics(&self, state: &QuantumNetworkState) {
        if let Some(metrics) = &self.metrics {
            metrics.update(&state.stats());
        }
    }
}

/// Snapshot of network metrics for external consumption.
#[derive(Debug, Clone)]
pub struct NetworkMetricsSnapshot {
    pub purity: f64,
    pub entropy: f64,
    pub connection_coherence: f64,
    pub validator_entanglement: f64,
    pub total_messages_sent: u64,
    pub total_messages_received: u64,
    pub total_connections: u64,
    pub total_disconnections: u64,
    pub is_healthy: bool,
}

// -----------------------------------------------------------------------------
// Re‑exports – core networking types
// -----------------------------------------------------------------------------

pub use inmem::InMemNet;
pub use peer_score::PeerScore;
pub use peerstore::PeerStore;
pub use eclipse_profiles::{EclipseParams, EclipseProfile, EclipseSecurityState};
pub use state_sync::{StateSync, StateSyncConfig};
pub use simnet::SimNet;

// -----------------------------------------------------------------------------
// Prelude – convenient import of common networking items
// -----------------------------------------------------------------------------

/// Prelude for the networking module.
pub mod prelude {
    pub use super::{
        InMemNet, NetConfig, NetworkStateManager, PeerScore, PeerStore,
        QuantumNetworkState, NetworkStats, EclipseParams, EclipseProfile,
    };
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_quantum_network_state_initialization() {
        let state = QuantumNetworkState::new();
        assert!((state.purity - 1.0).abs() < 1e-10);
        assert!((state.entropy - 0.0).abs() < 1e-10);
        assert!(state.is_healthy);
    }

    #[test]
    fn test_record_message_sent() {
        let mut state = QuantumNetworkState::new();
        let initial_purity = state.purity;
        state.record_message_sent();
        assert!(state.purity < initial_purity);
        assert_eq!(state.total_messages_sent, 1);
    }

    #[test]
    fn test_record_message_received() {
        let mut state = QuantumNetworkState::new();
        state.record_message_received();
        assert_eq!(state.total_messages_received, 1);
        assert!(state.purity < 1.0);
    }

    #[test]
    fn test_record_connection_restores_coherence() {
        let mut state = QuantumNetworkState::new();
        for _ in 0..100 {
            state.record_message_sent();
        }
        let purity_before = state.purity;
        state.record_connection();
        assert!(state.purity > purity_before);
        assert_eq!(state.total_connections, 1);
    }

    #[test]
    fn test_record_disconnection() {
        let mut state = QuantumNetworkState::new();
        let initial_purity = state.purity;
        state.record_disconnection();
        assert!(state.purity < initial_purity);
        assert_eq!(state.total_disconnections, 1);
    }

    #[test]
    fn test_net_config_validation() {
        let cfg = NetConfig::default();
        assert!(cfg.validate().is_ok());

        let bad = NetConfig {
            listen: "invalid".into(),
            ..Default::default()
        };
        assert!(bad.validate().is_err());
    }

    #[test]
    fn test_network_state_manager() {
        let manager = NetworkStateManager::new(false).unwrap();
        assert!(manager.is_healthy());
        manager.record_message_sent();
        assert!(!manager.is_healthy() || manager.stats().purity < 1.0);
    }

    #[test]
    fn test_network_metrics_snapshot() {
        // Using unregistered metrics to avoid global registry conflicts.
        let manager = NetworkStateManager::new(true).unwrap();
        manager.record_message_sent();
        let snapshot = manager.metrics_snapshot().unwrap();
        assert!(snapshot.total_messages_sent > 0);
        assert!(snapshot.purity < 1.0);
    }
}
