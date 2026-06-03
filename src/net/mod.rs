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

// -----------------------------------------------------------------------------
// Quantum Network State (shared across networking modules)
// -----------------------------------------------------------------------------

/// Quantum state of the overall networking subsystem.
///
/// Tracks the density matrix properties of the P2P network, providing
/// observables for monitoring network health.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
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
        self.total_messages_sent = self.total_messages_sent.wrapping_add(1);
        self.apply_operation_decoherence();
    }

    /// Record a message received event.
    pub fn record_message_received(&mut self) {
        self.total_messages_received = self.total_messages_received.wrapping_add(1);
        self.apply_operation_decoherence();
    }

    /// Record a new connection.
    pub fn record_connection(&mut self) {
        self.total_connections = self.total_connections.wrapping_add(1);
        // New connections restore some coherence
        self.connection_coherence = (self.connection_coherence * 1.001).min(1.0);
        self.recompute();
    }

    /// Record a disconnection.
    pub fn record_disconnection(&mut self) {
        self.total_disconnections = self.total_disconnections.wrapping_add(1);
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
}

// -----------------------------------------------------------------------------
// Networking Configuration
// -----------------------------------------------------------------------------

/// Global networking configuration.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
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
        Ok(())
    }
}

// -----------------------------------------------------------------------------
// Re‑exports – core networking types
// -----------------------------------------------------------------------------

pub use inmem::InMemNet;
pub use peer_score::PeerScore;
pub use peerstore::PeerStore;
pub use eclipse_profiles::{EclipseParams, EclipseProfile, EclipseSecurityState};

// -----------------------------------------------------------------------------
// Prelude – convenient import of common networking items
// -----------------------------------------------------------------------------

/// Prelude for the networking module.
pub mod prelude {
    pub use super::{
        InMemNet, NetConfig, PeerScore, PeerStore, QuantumNetworkState,
        EclipseParams, EclipseProfile,
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
        // First decohere
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
}
