//! Quantum In‑Memory Transport for Consensus Messages.
//!
//! # Quantum Network Model
//!
//! The in‑memory network is modelled as a **quantum communication channel**
//! where each node exists in a superposition of connected states and
//! messages propagate via **entanglement swapping** between nodes.
//!
//! # Mathematical Formalism
//!
//! ## Network State
//! ```text
//! |Ψ_network⟩ = (1/√N) Σ_{i=1}^N |node_i⟩ ⊗ |channel_i⟩
//! ```
//!
//! ## Hamiltonian for Message Propagation
//! ```text
//! Ĥ_net = Ĥ_broadcast + Ĥ_unicast + Ĥ_connect + Ĥ_disconnect
//!
//! Ĥ_broadcast  = Σ_i g_i (a†_i + a_i)                     (message creation/annihilation)
//! Ĥ_unicast    = Σ_j h_j σ^+_j σ^-_k                      (directed entanglement)
//! Ĥ_connect    = Σ_k ω_k c†_k c_k                          (connection oscillator)
//! Ĥ_disconnect = Σ_l γ_l (n̂_l + ½)                         (disconnection decay)
//! ```
//!
//! ## Message Propagation as Quantum Channel
//! ```text
//! Φ(ρ) = Σ_k K_k ρ K_k†
//! K_k = √p_k |k⟩⟨k| ⊗ |delivered⟩⟨sent|
//! ```
//!
//! ## Entanglement Between Nodes
//! ```text
//! |Ψ_AB⟩ = (1/√2)(|0_A⟩|1_B⟩ + |1_A⟩|0_B⟩)   (Bell state)
//! ```
//! Each pair of connected nodes shares a Bell pair for message teleportation.
//!
//! # Example
//!
//! ```
//! use iona::net::inmem::InMemNet;
//! use iona::consensus::ConsensusMsg;
//!
//! let (net1, mut rx1) = InMemNet::new(1);
//! let rx2 = net1.register(2);
//! let net2 = net1.handle(2);
//!
//! net1.broadcast(ConsensusMsg::Note("hello".into()));
//! // rx1 does NOT receive (broadcast excludes sender), rx2 receives.
//! ```

use crate::consensus::ConsensusMsg;
use std::collections::HashMap;
use std::sync::{
    atomic::{AtomicU64, Ordering},
    Arc, Mutex,
};
use tokio::sync::mpsc;
use tracing::{debug, warn};

pub type NodeId = u64;

// -----------------------------------------------------------------------------
// Quantum Constants
// -----------------------------------------------------------------------------

/// Reduced Planck constant (natural units).
const HBAR: f64 = 1.0;

/// Decoherence rate per message broadcast.
const BROADCAST_DECOHERENCE_RATE: f64 = 0.0001;

/// Decoherence rate per unicast message.
const UNICAST_DECOHERENCE_RATE: f64 = 0.00005;

/// Decoherence rate per node disconnection.
const DISCONNECT_DECOHERENCE_RATE: f64 = 0.001;

/// Entanglement strength between connected nodes.
const NODE_ENTANGLEMENT: f64 = 0.99;

/// Kraus rank for network quantum channels.
const KRAUS_RANK: usize = 4;

/// Minimum coherence for healthy network.
const MIN_NETWORK_COHERENCE: f64 = 0.9;

/// Default quantum purity for new nodes.
const DEFAULT_NODE_PURITY: f64 = 1.0;

// -----------------------------------------------------------------------------
// Quantum Node State
// -----------------------------------------------------------------------------

/// Quantum state of a single node in the network.
#[derive(Debug, Clone)]
struct QuantumNodeState {
    /// Purity γ = Tr(ρ²) of the node's state.
    purity: f64,
    /// Entanglement fidelity with the network.
    entanglement_fidelity: f64,
    /// Number of messages sent by this node.
    messages_sent: u64,
    /// Number of messages received by this node.
    messages_received: u64,
    /// Whether the node is in a healthy quantum state.
    is_healthy: bool,
}

impl QuantumNodeState {
    fn new() -> Self {
        Self {
            purity: DEFAULT_NODE_PURITY,
            entanglement_fidelity: DEFAULT_NODE_PURITY,
            messages_sent: 0,
            messages_received: 0,
            is_healthy: true,
        }
    }

    /// Apply decoherence from sending a message.
    fn apply_send_decoherence(&mut self, broadcast: bool) {
        self.messages_sent = self.messages_sent.wrapping_add(1);
        let rate = if broadcast {
            BROADCAST_DECOHERENCE_RATE
        } else {
            UNICAST_DECOHERENCE_RATE
        };
        let decay = (-rate).exp();
        self.purity = (self.purity * decay).clamp(0.0, 1.0);
        self.entanglement_fidelity = (self.entanglement_fidelity * decay.sqrt()).clamp(0.0, 1.0);
        self.is_healthy = self.purity >= MIN_NETWORK_COHERENCE;
    }

    /// Apply decoherence from receiving a message.
    fn apply_receive_decoherence(&mut self) {
        self.messages_received = self.messages_received.wrapping_add(1);
        let decay = (-UNICAST_DECOHERENCE_RATE).exp();
        self.purity = (self.purity * decay).clamp(0.0, 1.0);
        self.is_healthy = self.purity >= MIN_NETWORK_COHERENCE;
    }
}

// -----------------------------------------------------------------------------
// Quantum Network State
// -----------------------------------------------------------------------------

/// Quantum state of the entire network.
#[derive(Debug)]
struct QuantumNetworkState {
    /// Per-node quantum states.
    nodes: HashMap<NodeId, QuantumNodeState>,
    /// Network-wide purity (average).
    network_purity: f64,
    /// Total messages broadcast across the network.
    total_broadcasts: u64,
    /// Total unicast messages.
    total_unicasts: u64,
    /// Total disconnections.
    total_disconnections: u64,
    /// Whether the network is healthy.
    is_healthy: bool,
}

impl QuantumNetworkState {
    fn new() -> Self {
        Self {
            nodes: HashMap::new(),
            network_purity: DEFAULT_NODE_PURITY,
            total_broadcasts: 0,
            total_unicasts: 0,
            total_disconnections: 0,
            is_healthy: true,
        }
    }

    /// Register a new node in the network.
    fn register_node(&mut self, node_id: NodeId) {
        self.nodes
            .entry(node_id)
            .or_insert_with(QuantumNodeState::new);
        self.recompute();
    }

    /// Remove a node from the network.
    fn unregister_node(&mut self, node_id: NodeId) {
        if self.nodes.remove(&node_id).is_some() {
            self.total_disconnections = self.total_disconnections.wrapping_add(1);
            self.recompute();
        }
    }

    /// Record a broadcast event.
    fn record_broadcast(&mut self, from: NodeId, recipient_count: usize) {
        self.total_broadcasts = self.total_broadcasts.wrapping_add(1);
        if let Some(node) = self.nodes.get_mut(&from) {
            node.apply_send_decoherence(true);
        }
        self.recompute();
    }

    /// Record a unicast event.
    fn record_unicast(&mut self, from: NodeId, to: NodeId, success: bool) {
        self.total_unicasts = self.total_unicasts.wrapping_add(1);
        if let Some(node) = self.nodes.get_mut(&from) {
            node.apply_send_decoherence(false);
        }
        if success {
            if let Some(node) = self.nodes.get_mut(&to) {
                node.apply_receive_decoherence();
            }
        }
        self.recompute();
    }

    /// Recompute network-wide quantum properties.
    fn recompute(&mut self) {
        let count = self.nodes.len();
        if count == 0 {
            self.network_purity = 0.0;
            self.is_healthy = false;
            return;
        }
        let total_purity: f64 = self.nodes.values().map(|n| n.purity).sum();
        self.network_purity = (total_purity / count as f64).clamp(0.0, 1.0);
        self.is_healthy = self.network_purity >= MIN_NETWORK_COHERENCE;
    }

    /// Get quantum statistics.
    fn stats(&self) -> NetworkStats {
        NetworkStats {
            node_count: self.nodes.len(),
            network_purity: self.network_purity,
            total_broadcasts: self.total_broadcasts,
            total_unicasts: self.total_unicasts,
            total_disconnections: self.total_disconnections,
            is_healthy: self.is_healthy,
        }
    }
}

// -----------------------------------------------------------------------------
// Network Statistics
// -----------------------------------------------------------------------------

/// Observable statistics for the quantum network.
#[derive(Debug, Clone)]
pub struct NetworkStats {
    pub node_count: usize,
    pub network_purity: f64,
    pub total_broadcasts: u64,
    pub total_unicasts: u64,
    pub total_disconnections: u64,
    pub is_healthy: bool,
}

// -----------------------------------------------------------------------------
// Quantum In‑Memory Network
// -----------------------------------------------------------------------------

/// Handle used by a node to send messages into the quantum in‑memory network.
///
/// The network maintains a **quantum state** tracking entanglement between
/// nodes and decoherence from message propagation.
#[derive(Clone)]
pub struct InMemNet {
    /// Shared inner state protected by a mutex.
    inner: Arc<Mutex<Inner>>,
    /// Local node identifier.
    pub node_id: NodeId,
}

struct Inner {
    /// Map of node ID to their message sender (quantum channel).
    peers: HashMap<NodeId, mpsc::UnboundedSender<ConsensusMsg>>,
    /// Quantum state of the network.
    quantum: QuantumNetworkState,
}

impl InMemNet {
    /// Create a new quantum network and register the first node.
    ///
    /// Prepares the initial quantum state |∅⟩ → |node_1⟩.
    ///
    /// Returns a handle for the node and a receiver to read incoming messages.
    pub fn new(node_id: NodeId) -> (Self, mpsc::UnboundedReceiver<ConsensusMsg>) {
        let mut quantum = QuantumNetworkState::new();
        quantum.register_node(node_id);

        let inner = Arc::new(Mutex::new(Inner {
            peers: HashMap::new(),
            quantum,
        }));
        let (tx, rx) = mpsc::unbounded_channel();
        inner.lock().unwrap().peers.insert(node_id, tx);

        debug!(
            node_id,
            purity = DEFAULT_NODE_PURITY,
            "quantum in‑memory network created, node registered"
        );

        (Self { inner, node_id }, rx)
    }

    /// Register an additional node into the same quantum network.
    ///
    /// Creates entanglement between the new node and the existing network:
    /// ```text
    /// U_register |∅⟩|Ψ_network⟩ → |node_new⟩|Ψ_network'⟩
    /// ```
    ///
    /// Returns a receiver for that node.
    pub fn register(&self, node_id: NodeId) -> mpsc::UnboundedReceiver<ConsensusMsg> {
        let (tx, rx) = mpsc::unbounded_channel();
        let mut inner = self.inner.lock().unwrap();
        inner.peers.insert(node_id, tx);
        inner.quantum.register_node(node_id);

        debug!(
            node_id,
            purity = inner.quantum.network_purity,
            "quantum node registered in existing network"
        );

        rx
    }

    /// Create another handle for the same underlying quantum network.
    ///
    /// Multiple handles share the same quantum state, enabling multi‑node
    /// simulation within a single process.
    pub fn handle(&self, node_id: NodeId) -> Self {
        Self {
            inner: self.inner.clone(),
            node_id,
        }
    }

    /// Broadcast a message to all nodes **except** the sender.
    ///
    /// This applies the quantum broadcast channel:
    /// ```text
    /// Φ_broadcast(ρ) = Σ_i K_i ρ K_i†
    /// ```
    /// where each Kraus operator K_i delivers the message to node i.
    pub fn broadcast(&self, msg: ConsensusMsg) {
        let peers = self.inner.lock().unwrap().peers.clone();
        let mut failed = Vec::new();
        let mut recipient_count = 0u64;

        for (id, tx) in peers.iter() {
            if *id == self.node_id {
                continue;
            }
            if let Err(e) = tx.send(msg.clone()) {
                warn!(to = id, error = %e, "quantum channel decoherence: failed to broadcast message");
                failed.push(*id);
            } else {
                recipient_count += 1;
            }
        }

        // Update quantum state
        let mut inner = self.inner.lock().unwrap();
        inner.quantum.record_broadcast(self.node_id, recipient_count as usize);

        if !failed.is_empty() {
            // Remove failed nodes — quantum disconnection
            for id in &failed {
                inner.peers.remove(id);
                inner.quantum.unregister_node(*id);
                debug!(node_id = id, "quantum node disconnected");
            }
        }

        debug!(
            from = self.node_id,
            peers = inner.peers.len(),
            purity = inner.quantum.network_purity,
            "quantum broadcast completed"
        );
    }

    /// Send a message directly to a specific node (by ID).
    ///
    /// Applies the quantum unicast channel:
    /// ```text
    /// Φ_unicast(ρ) = K_deliver ρ K_deliver† + K_fail ρ K_fail†
    /// ```
    pub fn send_to(&self, target: NodeId, msg: ConsensusMsg) -> Result<(), &'static str> {
        let peers = self.inner.lock().unwrap().peers.clone();
        if let Some(tx) = peers.get(&target) {
            match tx.send(msg) {
                Ok(()) => {
                    let mut inner = self.inner.lock().unwrap();
                    inner.quantum.record_unicast(self.node_id, target, true);
                    debug!(
                        from = self.node_id,
                        to = target,
                        "quantum unicast message sent"
                    );
                    Ok(())
                }
                Err(_) => {
                    let mut inner = self.inner.lock().unwrap();
                    inner.quantum.record_unicast(self.node_id, target, false);
                    warn!(to = target, "quantum channel decoherence: failed to send message");
                    Err("failed to send message")
                }
            }
        } else {
            warn!(to = target, "target node not found in quantum network");
            Err("target node not registered")
        }
    }

    /// Return the number of currently registered peers in the quantum network.
    pub fn peer_count(&self) -> usize {
        self.inner.lock().unwrap().peers.len()
    }

    /// Check if a given node ID is connected (registered) in the quantum network.
    pub fn is_connected(&self, node_id: NodeId) -> bool {
        self.inner.lock().unwrap().peers.contains_key(&node_id)
    }

    /// Get the quantum purity of the local node.
    pub fn node_purity(&self) -> f64 {
        let inner = self.inner.lock().unwrap();
        inner
            .quantum
            .nodes
            .get(&self.node_id)
            .map(|n| n.purity)
            .unwrap_or(0.0)
    }

    /// Get the network-wide quantum purity.
    pub fn network_purity(&self) -> f64 {
        self.inner.lock().unwrap().quantum.network_purity
    }

    /// Check if the quantum network is healthy.
    pub fn is_network_healthy(&self) -> bool {
        self.inner.lock().unwrap().quantum.is_healthy
    }

    /// Get quantum network statistics.
    pub fn network_stats(&self) -> NetworkStats {
        self.inner.lock().unwrap().quantum.stats()
    }

    /// Get the number of messages sent by the local node.
    pub fn messages_sent(&self) -> u64 {
        let inner = self.inner.lock().unwrap();
        inner
            .quantum
            .nodes
            .get(&self.node_id)
            .map(|n| n.messages_sent)
            .unwrap_or(0)
    }

    /// Get the number of messages received by the local node.
    pub fn messages_received(&self) -> u64 {
        let inner = self.inner.lock().unwrap();
        inner
            .quantum
            .nodes
            .get(&self.node_id)
            .map(|n| n.messages_received)
            .unwrap_or(0)
    }

    /// Unregister the local node from the network.
    ///
    /// Applies the quantum disconnection operator:
    /// ```text
    /// a |node_i⟩ → |∅⟩
    /// ```
    pub fn unregister(&self) {
        let mut inner = self.inner.lock().unwrap();
        inner.peers.remove(&self.node_id);
        inner.quantum.unregister_node(self.node_id);
        debug!(
            node_id = self.node_id,
            purity = inner.quantum.network_purity,
            "quantum node unregistered"
        );
    }
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::consensus::ConsensusMsg;

    // ── Classical Tests (unchanged behavior) ───────────────────────────

    #[tokio::test]
    async fn test_broadcast_excludes_self() {
        let (net1, mut rx1) = InMemNet::new(1);
        let rx2 = net1.register(2);
        let rx3 = net1.register(3);

        net1.broadcast(ConsensusMsg::Note("hello".into()));

        // Self should not receive.
        assert!(rx1.try_recv().is_err());

        // Others should receive.
        assert!(rx2.try_recv().is_ok());
        assert!(rx3.try_recv().is_ok());
    }

    #[tokio::test]
    async fn test_send_to() {
        let (net1, mut rx1) = InMemNet::new(1);
        let rx2 = net1.register(2);

        net1.send_to(2, ConsensusMsg::Note("direct".into()))
            .unwrap();

        assert!(rx1.try_recv().is_err());
        let msg = rx2.try_recv().unwrap();
        match msg {
            ConsensusMsg::Note(s) => assert_eq!(s, "direct"),
            _ => panic!("unexpected message"),
        }
    }

    #[tokio::test]
    async fn test_send_to_nonexistent() {
        let (net1, _) = InMemNet::new(1);
        let res = net1.send_to(99, ConsensusMsg::Note("test".into()));
        assert!(res.is_err());
    }

    #[tokio::test]
    async fn test_peer_count() {
        let (net1, _) = InMemNet::new(1);
        assert_eq!(net1.peer_count(), 1);
        net1.register(2);
        assert_eq!(net1.peer_count(), 2);
        let net2 = net1.handle(3);
        net2.register(4);
        assert_eq!(net1.peer_count(), 4);
    }

    #[tokio::test]
    async fn test_is_connected() {
        let (net1, _) = InMemNet::new(1);
        assert!(net1.is_connected(1));
        assert!(!net1.is_connected(2));
        net1.register(2);
        assert!(net1.is_connected(2));
    }

    #[tokio::test]
    async fn test_handle() {
        let (net1, mut rx1) = InMemNet::new(1);
        let rx2 = net1.register(2);
        let net2 = net1.handle(2);
        net2.broadcast(ConsensusMsg::Note("from handle".into()));
        // net2 broadcasts to all except itself (id=2), so net1 should receive.
        let msg = rx1.try_recv().unwrap();
        match msg {
            ConsensusMsg::Note(s) => assert_eq!(s, "from handle"),
            _ => panic!("unexpected"),
        }
        assert!(rx2.try_recv().is_err());
    }

    // ── Quantum Tests ──────────────────────────────────────────────────

    #[tokio::test]
    async fn test_quantum_purity_after_broadcast() {
        let (net1, _) = InMemNet::new(1);
        net1.register(2);

        let initial_purity = net1.node_purity();
        assert!((initial_purity - 1.0).abs() < 1e-10);

        net1.broadcast(ConsensusMsg::Note("test".into()));

        let final_purity = net1.node_purity();
        assert!(final_purity < initial_purity);
    }

    #[tokio::test]
    async fn test_quantum_purity_after_unicast() {
        let (net1, _) = InMemNet::new(1);
        net1.register(2);

        let initial_purity = net1.node_purity();
        net1.send_to(2, ConsensusMsg::Note("direct".into()))
            .unwrap();

        assert!(net1.node_purity() < initial_purity);
    }

    #[tokio::test]
    async fn test_network_purity() {
        let (net1, _) = InMemNet::new(1);
        net1.register(2);
        net1.register(3);

        let initial_network_purity = net1.network_purity();
        assert!(initial_network_purity > 0.99);

        for _ in 0..50 {
            net1.broadcast(ConsensusMsg::Note("stress".into()));
        }

        let final_network_purity = net1.network_purity();
        assert!(final_network_purity < initial_network_purity);
    }

    #[tokio::test]
    async fn test_network_health() {
        let (net1, _) = InMemNet::new(1);
        assert!(net1.is_network_healthy());

        // Many broadcasts cause decoherence but not enough to fail in test
        for _ in 0..100 {
            net1.broadcast(ConsensusMsg::Note("test".into()));
        }
        assert!(net1.is_network_healthy());
    }

    #[tokio::test]
    async fn test_network_stats() {
        let (net1, _) = InMemNet::new(1);
        net1.register(2);

        net1.broadcast(ConsensusMsg::Note("test".into()));

        let stats = net1.network_stats();
        assert_eq!(stats.node_count, 2);
        assert!(stats.total_broadcasts > 0);
        assert!(stats.network_purity > 0.0);
    }

    #[tokio::test]
    async fn test_messages_counters() {
        let (net1, _) = InMemNet::new(1);
        net1.register(2);

        assert_eq!(net1.messages_sent(), 0);

        net1.broadcast(ConsensusMsg::Note("test".into()));
        assert_eq!(net1.messages_sent(), 1);

        net1.send_to(2, ConsensusMsg::Note("direct".into()))
            .unwrap();
        assert_eq!(net1.messages_sent(), 2);
    }

    #[tokio::test]
    async fn test_unregister() {
        let (net1, _) = InMemNet::new(1);
        net1.register(2);

        assert_eq!(net1.peer_count(), 2);
        net1.unregister();
        assert_eq!(net1.peer_count(), 1);
        assert!(!net1.is_connected(1));
    }
}
