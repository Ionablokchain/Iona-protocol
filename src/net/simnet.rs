//! In-memory simnet transport for integration testing.
//!
//! This simnet can deliver:
//! - consensus broadcasts (e.g. Proposal/Vote)
//! - block request/response used when proposals arrive without full blocks
//!
//! Additional features:
//! - deterministic packet loss (drop) and delay simulation
//! - bounded consensus history + replay to late joiners
//! - network partitioning simulation
//! - optional Prometheus metrics
//! - configuration validation
//!
//! # Example
//!
//! ```
//! use iona::net::simnet::{SimNet, SimNetConfig};
//! use iona::consensus::ConsensusMsg;
//!
//! let (net1, mut rx1) = SimNet::new(1);
//! let rx2 = net1.register(2);
//! net1.broadcast_consensus(ConsensusMsg::Note("hello".into()));
//! ```

use crate::consensus::ConsensusMsg;
use crate::types::{Block, Hash32};
use parking_lot::Mutex;
use prometheus::{register_counter, register_gauge, Counter, Gauge};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::mpsc;
use tracing::{debug, warn};

pub type NodeId = u64;

// -----------------------------------------------------------------------------
// NetMsg
// -----------------------------------------------------------------------------

/// Network message types supported by the simnet.
#[derive(Clone, Debug)]
pub enum NetMsg {
    Consensus { from: NodeId, msg: ConsensusMsg },
    BlockRequest { from: NodeId, id: Hash32 },
    BlockResponse { from: NodeId, block: Block },
}

// -----------------------------------------------------------------------------
// SimNetConfig
// -----------------------------------------------------------------------------

/// Simnet configuration.
/// Drop probabilities are in parts-per-million (ppm): 1_000_000 = 100%.
#[derive(Clone, Debug)]
pub struct SimNetConfig {
    pub drop_ppm_consensus: u32,
    pub drop_ppm_block: u32,
    pub min_delay_ms: u64,
    pub max_delay_ms: u64,
    pub history_limit: usize,
    pub seed: u64,
    /// Whether to enable Prometheus metrics.
    pub enable_metrics: bool,
}

impl Default for SimNetConfig {
    fn default() -> Self {
        Self {
            drop_ppm_consensus: 0,
            drop_ppm_block: 0,
            min_delay_ms: 0,
            max_delay_ms: 0,
            history_limit: 64,
            seed: 0xC0FFEE_u64,
            enable_metrics: false,
        }
    }
}

impl SimNetConfig {
    /// Validate the configuration.
    pub fn validate(&self) -> Result<(), String> {
        if self.drop_ppm_consensus > 1_000_000 {
            return Err("drop_ppm_consensus must be <= 1_000_000".into());
        }
        if self.drop_ppm_block > 1_000_000 {
            return Err("drop_ppm_block must be <= 1_000_000".into());
        }
        if self.min_delay_ms > self.max_delay_ms {
            return Err("min_delay_ms must be <= max_delay_ms".into());
        }
        if self.history_limit == 0 {
            return Err("history_limit must be > 0".into());
        }
        Ok(())
    }
}

// -----------------------------------------------------------------------------
// Metrics
// -----------------------------------------------------------------------------

/// Prometheus metrics for the simnet.
#[derive(Clone)]
pub struct SimNetMetrics {
    /// Total peers currently registered.
    pub peers: Gauge,
    /// Total messages sent (excluding dropped).
    pub messages_sent: Counter,
    /// Total messages dropped due to simulated loss.
    pub messages_dropped: Counter,
    /// Total messages delayed.
    pub messages_delayed: Counter,
    /// Total consensus broadcasts.
    pub broadcasts_total: Counter,
    /// Total block requests.
    pub block_requests_total: Counter,
    /// Total block responses.
    pub block_responses_total: Counter,
}

impl SimNetMetrics {
    /// Create and register metrics with the global Prometheus registry.
    pub fn new() -> Result<Self, prometheus::Error> {
        Ok(Self {
            peers: register_gauge!("iona_simnet_peers", "Number of registered peers")?,
            messages_sent: register_counter!("iona_simnet_messages_sent_total", "Total messages sent")?,
            messages_dropped: register_counter!("iona_simnet_messages_dropped_total", "Total messages dropped")?,
            messages_delayed: register_counter!("iona_simnet_messages_delayed_total", "Total messages delayed")?,
            broadcasts_total: register_counter!("iona_simnet_broadcasts_total", "Total consensus broadcasts")?,
            block_requests_total: register_counter!("iona_simnet_block_requests_total", "Total block requests")?,
            block_responses_total: register_counter!("iona_simnet_block_responses_total", "Total block responses")?,
        })
    }

    /// Create an unregistered instance (for tests or disabled metrics).
    pub fn new_unregistered() -> Self {
        Self {
            peers: Gauge::new("iona_simnet_peers", "Peers").unwrap(),
            messages_sent: Counter::new("iona_simnet_messages_sent_total", "Sent").unwrap(),
            messages_dropped: Counter::new("iona_simnet_messages_dropped_total", "Dropped").unwrap(),
            messages_delayed: Counter::new("iona_simnet_messages_delayed_total", "Delayed").unwrap(),
            broadcasts_total: Counter::new("iona_simnet_broadcasts_total", "Broadcasts").unwrap(),
            block_requests_total: Counter::new("iona_simnet_block_requests_total", "Block requests").unwrap(),
            block_responses_total: Counter::new("iona_simnet_block_responses_total", "Block responses").unwrap(),
        }
    }

    fn update_peers(&self, count: usize) {
        self.peers.set(count as f64);
    }
}

// -----------------------------------------------------------------------------
// Inner state
// -----------------------------------------------------------------------------

struct Inner {
    peers: HashMap<NodeId, mpsc::UnboundedSender<NetMsg>>,
    cfg: SimNetConfig,
    rng: u64,
    consensus_history: Vec<ConsensusMsg>,
    partitions: HashMap<NodeId, u64>,
    partitioning_enabled: bool,
    metrics: Option<Arc<SimNetMetrics>>,
}

// -----------------------------------------------------------------------------
// SimNet
// -----------------------------------------------------------------------------

/// Handle used by a node to interact with the simnet.
#[derive(Clone)]
pub struct SimNet {
    inner: Arc<Mutex<Inner>>,
    pub node_id: NodeId,
}

impl SimNet {
    /// Create a new simnet with default configuration.
    #[must_use]
    pub fn new(node_id: NodeId) -> (Self, mpsc::UnboundedReceiver<NetMsg>) {
        Self::with_config(node_id, SimNetConfig::default())
    }

    /// Create a new simnet with a custom configuration.
    #[must_use]
    pub fn with_config(
        node_id: NodeId,
        cfg: SimNetConfig,
    ) -> (Self, mpsc::UnboundedReceiver<NetMsg>) {
        // Validate config; if invalid, panic (or return Result? but signature returns tuple)
        // For production use, we could change signature to Result, but to maintain compatibility,
        // we can use expect and log. However, better to provide a `try_with_config`.
        // We'll add a separate `try_with_config` returning Result and keep this for compatibility.
        if let Err(e) = cfg.validate() {
            panic!("Invalid simnet configuration: {}", e);
        }

        let metrics = if cfg.enable_metrics {
            Some(Arc::new(SimNetMetrics::new().unwrap_or_else(|_| {
                warn!("Failed to register simnet metrics; using unregistered");
                SimNetMetrics::new_unregistered()
            })))
        } else {
            None
        };

        let inner = Arc::new(Mutex::new(Inner {
            peers: HashMap::new(),
            rng: cfg.seed ^ (node_id.wrapping_mul(0x9E37_79B9_7F4A_7C15)),
            consensus_history: Vec::new(),
            partitions: HashMap::new(),
            partitioning_enabled: false,
            cfg,
            metrics,
        }));
        let (tx, rx) = mpsc::unbounded_channel();
        {
            let mut g = inner.lock();
            g.peers.insert(node_id, tx);
            g.partitions.insert(node_id, 0);
            if let Some(m) = &g.metrics {
                m.update_peers(g.peers.len());
            }
        }
        debug!(node_id, "simnet created");
        (Self { inner, node_id }, rx)
    }

    /// Create a new simnet with configuration, returning a Result.
    pub fn try_with_config(
        node_id: NodeId,
        cfg: SimNetConfig,
    ) -> Result<(Self, mpsc::UnboundedReceiver<NetMsg>), String> {
        cfg.validate()?;
        let metrics = if cfg.enable_metrics {
            Some(Arc::new(SimNetMetrics::new().map_err(|e| e.to_string())?))
        } else {
            None
        };

        let inner = Arc::new(Mutex::new(Inner {
            peers: HashMap::new(),
            rng: cfg.seed ^ (node_id.wrapping_mul(0x9E37_79B9_7F4A_7C15)),
            consensus_history: Vec::new(),
            partitions: HashMap::new(),
            partitioning_enabled: false,
            cfg,
            metrics,
        }));
        let (tx, rx) = mpsc::unbounded_channel();
        {
            let mut g = inner.lock();
            g.peers.insert(node_id, tx);
            g.partitions.insert(node_id, 0);
            if let Some(m) = &g.metrics {
                m.update_peers(g.peers.len());
            }
        }
        debug!(node_id, "simnet created with custom config");
        Ok((Self { inner, node_id }, rx))
    }

    /// Register a new node in the simnet.
    pub fn register(&self, node_id: NodeId) -> mpsc::UnboundedReceiver<NetMsg> {
        let (tx, rx) = mpsc::unbounded_channel();
        let mut g = self.inner.lock();
        g.peers.insert(node_id, tx);
        g.partitions.insert(node_id, 0);
        if let Some(m) = &g.metrics {
            m.update_peers(g.peers.len());
        }
        debug!(node_id, "registered node in simnet");
        rx
    }

    /// Enable or disable network partitioning.
    pub fn enable_partitioning(&self, enabled: bool) {
        let mut g = self.inner.lock();
        g.partitioning_enabled = enabled;
        debug!(enabled, "partitioning toggled");
    }

    /// Assign a node to a partition id (0 by default).
    pub fn set_partition(&self, node_id: NodeId, partition_id: u64) {
        let mut g = self.inner.lock();
        g.partitions.insert(node_id, partition_id);
        debug!(node_id, partition_id, "node assigned to partition");
    }

    /// Snapshot of bounded consensus history (for tests/diagnostics).
    #[must_use]
    pub fn consensus_history(&self) -> Vec<ConsensusMsg> {
        self.inner
            .lock()
            .consensus_history
            .clone()
    }

    /// Create another handle for the same underlying network with a different node id.
    #[must_use]
    pub fn handle(&self, node_id: NodeId) -> Self {
        Self {
            inner: self.inner.clone(),
            node_id,
        }
    }

    /// Replay bounded consensus history to a given node (useful for late joiners).
    pub fn replay_consensus_to(&self, to: NodeId) {
        let (tx, msgs, cfg, drop_ppm, from) = {
            let inner = self.inner.lock();
            let tx = match inner.peers.get(&to) {
                Some(t) => t.clone(),
                None => {
                    warn!(to, "attempted to replay to unknown node");
                    return;
                }
            };
            (
                tx,
                inner.consensus_history.clone(),
                inner.cfg.clone(),
                inner.cfg.drop_ppm_consensus,
                self.node_id,
            )
        };
        debug!(to, count = msgs.len(), "replaying consensus history");
        for msg in msgs {
            // We'll simulate impairments outside lock to avoid holding lock during async.
            // But we need RNG state from inner; we can create a temporary RNG deterministic per message.
            let (drop_it, delay_ms) = Self::compute_impairment(&cfg, drop_ppm, &msg);
            if drop_it {
                if let Some(m) = &self.inner.lock().metrics {
                    m.messages_dropped.inc();
                }
                continue;
            }
            if let Some(m) = &self.inner.lock().metrics {
                if delay_ms > 0 {
                    m.messages_delayed.inc();
                }
                m.messages_sent.inc();
            }
            if delay_ms == 0 {
                let _ = tx.send(NetMsg::Consensus { from, msg });
            } else {
                tokio::spawn(async move {
                    tokio::time::sleep(std::time::Duration::from_millis(delay_ms)).await;
                    let _ = tx.send(NetMsg::Consensus { from, msg });
                });
            }
        }
    }

    /// Send a message directly to a specific node.
    pub fn send_to(&self, to: NodeId, msg: NetMsg) {
        let (tx, cfg, drop_ppm, allow) = {
            let inner = self.inner.lock();
            let tx = match inner.peers.get(&to) {
                Some(t) => t.clone(),
                None => {
                    warn!(to, "attempted to send to unknown node");
                    return;
                }
            };
            let drop_ppm = match msg {
                NetMsg::Consensus { .. } => inner.cfg.drop_ppm_consensus,
                NetMsg::BlockRequest { .. } | NetMsg::BlockResponse { .. } => {
                    inner.cfg.drop_ppm_block
                }
            };
            let allow = if inner.partitioning_enabled {
                let a = *inner.partitions.get(&self.node_id).unwrap_or(&0);
                let b = *inner.partitions.get(&to).unwrap_or(&0);
                a == b
            } else {
                true
            };
            (tx, inner.cfg.clone(), drop_ppm, allow)
        };
        if !allow {
            debug!(from = self.node_id, to, "message dropped due to partitioning");
            return;
        }
        self.send_with_impairments(tx, cfg, drop_ppm, msg);
    }

    /// Broadcast a consensus message to all other nodes.
    pub fn broadcast_consensus(&self, msg: ConsensusMsg) {
        let (peers, cfg, drop_ppm, from, cfg_partitioning, partitions, my_part) = {
            let mut inner = self.inner.lock();

            // update bounded history
            inner.consensus_history.push(msg.clone());
            if inner.consensus_history.len() > inner.cfg.history_limit {
                let extra = inner.consensus_history.len() - inner.cfg.history_limit;
                inner.consensus_history.drain(0..extra);
            }

            if let Some(m) = &inner.metrics {
                m.broadcasts_total.inc();
            }

            (
                inner.peers.clone(),
                inner.cfg.clone(),
                inner.cfg.drop_ppm_consensus,
                self.node_id,
                inner.partitioning_enabled,
                inner.partitions.clone(),
                inner.partitions.get(&self.node_id).copied().unwrap_or(0),
            )
        };

        // broadcast to all except self
        let mut sent = 0;
        for (id, tx) in peers.into_iter() {
            if id == self.node_id {
                continue;
            }
            if cfg_partitioning && partitions.get(&id).copied().unwrap_or(0) != my_part {
                continue;
            }
            self.send_with_impairments(
                tx,
                cfg.clone(),
                drop_ppm,
                NetMsg::Consensus {
                    from,
                    msg: msg.clone(),
                },
            );
            sent += 1;
        }
        debug!(from = self.node_id, sent, "broadcast consensus message");
    }

    /// Broadcast a block request to all other nodes.
    pub fn request_block(&self, id: Hash32) {
        let (peers, cfg, drop_ppm, from, cfg_partitioning, partitions, my_part) = {
            let inner = self.inner.lock();
            if let Some(m) = &inner.metrics {
                m.block_requests_total.inc();
            }
            (
                inner.peers.clone(),
                inner.cfg.clone(),
                inner.cfg.drop_ppm_block,
                self.node_id,
                inner.partitioning_enabled,
                inner.partitions.clone(),
                inner.partitions.get(&self.node_id).copied().unwrap_or(0),
            )
        };
        let mut sent = 0;
        for (pid, tx) in peers.into_iter() {
            if pid == self.node_id {
                continue;
            }
            if cfg_partitioning && partitions.get(&pid).copied().unwrap_or(0) != my_part {
                continue;
            }
            self.send_with_impairments(
                tx,
                cfg.clone(),
                drop_ppm,
                NetMsg::BlockRequest {
                    from,
                    id: id.clone(),
                },
            );
            sent += 1;
        }
        debug!(from = self.node_id, sent, "broadcast block request");
    }

    /// Request a block with simple retry + backoff.
    pub fn request_block_with_retry(&self, id: Hash32, attempts: u32, base_delay_ms: u64) {
        let net = self.clone();
        tokio::spawn(async move {
            let mut delay = base_delay_ms;
            for attempt in 0..attempts {
                net.request_block(id.clone());
                debug!(attempt, delay_ms = delay, "block request retry");
                tokio::time::sleep(std::time::Duration::from_millis(delay)).await;
                delay = (delay.saturating_mul(2)).min(200);
            }
        });
    }

    /// Get a snapshot of metrics (if enabled).
    pub fn metrics_snapshot(&self) -> Option<SimNetMetricsSnapshot> {
        let inner = self.inner.lock();
        inner.metrics.as_ref().map(|m| SimNetMetricsSnapshot {
            peers: m.peers.get() as usize,
            messages_sent: m.messages_sent.get(),
            messages_dropped: m.messages_dropped.get(),
            messages_delayed: m.messages_delayed.get(),
            broadcasts_total: m.broadcasts_total.get(),
            block_requests_total: m.block_requests_total.get(),
            block_responses_total: m.block_responses_total.get(),
        })
    }

    // -------------------------------------------------------------------------
    // Internal helpers
    // -------------------------------------------------------------------------

    /// Compute drop and delay deterministically based on config and message content.
    /// This is outside the lock to avoid holding it during async operations.
    fn compute_impairment(cfg: &SimNetConfig, drop_ppm: u32, msg: &NetMsg) -> (bool, u64) {
        // Use a simple deterministic hash based on message to get per-message variation.
        let mut x = cfg.seed ^ 0xA5A5_A5A5_A5A5_A5A5;
        // Mix in message type and some content
        let type_tag = match msg {
            NetMsg::Consensus { .. } => 1u64,
            NetMsg::BlockRequest { id, .. } => 2u64 ^ (id.0[0] as u64) ^ (id.0[1] as u64),
            NetMsg::BlockResponse { block, .. } => 3u64 ^ (block.header.height as u64),
        };
        x ^= type_tag;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        let r = ((x.wrapping_mul(0x2545F4914F6CDD1D) >> 32) & 0xFFFF_FFFF) as u32;
        let drop_it = drop_ppm != 0 && (r % 1_000_000) < drop_ppm;
        let delay_ms = if cfg.max_delay_ms <= cfg.min_delay_ms {
            cfg.min_delay_ms
        } else {
            let span = cfg.max_delay_ms - cfg.min_delay_ms + 1;
            cfg.min_delay_ms + (r as u64 % span)
        };
        (drop_it, delay_ms)
    }

    fn send_with_impairments(
        &self,
        tx: mpsc::UnboundedSender<NetMsg>,
        cfg: SimNetConfig,
        drop_ppm: u32,
        msg: NetMsg,
    ) {
        let (drop_it, delay_ms) = Self::compute_impairment(&cfg, drop_ppm, &msg);
        if drop_it {
            debug!(?msg, "message dropped (simulated loss)");
            if let Some(m) = &self.inner.lock().metrics {
                m.messages_dropped.inc();
            }
            return;
        }
        if let Some(m) = &self.inner.lock().metrics {
            if delay_ms > 0 {
                m.messages_delayed.inc();
            }
            m.messages_sent.inc();
            match &msg {
                NetMsg::Consensus { .. } => {},
                NetMsg::BlockRequest { .. } => {},
                NetMsg::BlockResponse { .. } => m.block_responses_total.inc(),
            }
        }
        if delay_ms == 0 {
            let _ = tx.send(msg);
            return;
        }
        tokio::spawn(async move {
            tokio::time::sleep(std::time::Duration::from_millis(delay_ms)).await;
            let _ = tx.send(msg);
        });
    }
}

/// Snapshot of simnet metrics for external consumption.
#[derive(Debug, Clone)]
pub struct SimNetMetricsSnapshot {
    pub peers: usize,
    pub messages_sent: u64,
    pub messages_dropped: u64,
    pub messages_delayed: u64,
    pub broadcasts_total: u64,
    pub block_requests_total: u64,
    pub block_responses_total: u64,
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::consensus::ConsensusMsg;
    use crate::types::Hash32;
    use tokio::time::{sleep, Duration};

    fn dummy_consensus_msg() -> ConsensusMsg {
        ConsensusMsg::Note("test".into())
    }

    #[tokio::test]
    async fn test_broadcast_delivery() {
        let (net1, mut rx1) = SimNet::new(1);
        let mut rx2 = net1.register(2);
        let msg = dummy_consensus_msg();

        net1.broadcast_consensus(msg.clone());
        assert!(rx1.try_recv().is_err());
        let received = rx2.recv().await.unwrap();
        match received {
            NetMsg::Consensus { from, msg: m } => {
                assert_eq!(from, 1);
                assert!(matches!(m, ConsensusMsg::Note(_)));
            }
            _ => panic!("unexpected message"),
        }
    }

    #[tokio::test]
    async fn test_send_to() {
        let (net1, mut rx1) = SimNet::new(1);
        let mut rx2 = net1.register(2);
        let msg = dummy_consensus_msg();

        net1.send_to(2, NetMsg::Consensus { from: 1, msg: msg.clone() });
        assert!(rx1.try_recv().is_err());
        let received = rx2.recv().await.unwrap();
        match received {
            NetMsg::Consensus { from, msg: m } => {
                assert_eq!(from, 1);
                assert!(matches!(m, ConsensusMsg::Note(_)));
            }
            _ => panic!("unexpected message"),
        }
    }

    #[tokio::test]
    async fn test_partitioning() {
        let (net1, _) = SimNet::new(1);
        let mut rx2 = net1.register(2);
        let mut rx3 = net1.register(3);

        net1.enable_partitioning(true);
        net1.set_partition(1, 1);
        net1.set_partition(2, 1);
        net1.set_partition(3, 2);

        net1.broadcast_consensus(dummy_consensus_msg());
        assert!(rx2.try_recv().is_ok());
        assert!(rx3.try_recv().is_err());
    }

    #[tokio::test]
    async fn test_replay_consensus_to() {
        let (net1, _) = SimNet::new(1);
        net1.register(2);
        net1.broadcast_consensus(dummy_consensus_msg());
        net1.broadcast_consensus(dummy_consensus_msg());

        let mut rx_late = net1.register(3);
        net1.replay_consensus_to(3);
        let msg1 = rx_late.recv().await.unwrap();
        let msg2 = rx_late.recv().await.unwrap();
        assert!(matches!(msg1, NetMsg::Consensus { .. }));
        assert!(matches!(msg2, NetMsg::Consensus { .. }));
    }

    #[tokio::test]
    async fn test_block_request_with_retry() {
        let (net1, _) = SimNet::new(1);
        let mut rx2 = net1.register(2);
        let hash = Hash32([0xAA; 32]);

        net1.request_block_with_retry(hash, 3, 10);
        sleep(Duration::from_millis(50)).await;
        assert!(rx2.try_recv().is_ok());
    }

    #[test]
    fn test_config_validation() {
        let mut cfg = SimNetConfig::default();
        assert!(cfg.validate().is_ok());

        cfg.drop_ppm_consensus = 1_000_001;
        assert!(cfg.validate().is_err());

        cfg.drop_ppm_consensus = 0;
        cfg.min_delay_ms = 100;
        cfg.max_delay_ms = 50;
        assert!(cfg.validate().is_err());

        cfg.min_delay_ms = 0;
        cfg.max_delay_ms = 100;
        cfg.history_limit = 0;
        assert!(cfg.validate().is_err());
    }

    #[tokio::test]
    async fn test_metrics_enabled() {
        let mut cfg = SimNetConfig::default();
        cfg.enable_metrics = true;
        let (net, _) = SimNet::try_with_config(1, cfg).unwrap();
        net.register(2);
        net.broadcast_consensus(dummy_consensus_msg());
        let snap = net.metrics_snapshot().unwrap();
        assert_eq!(snap.peers, 2);
        assert!(snap.broadcasts_total > 0);
        assert!(snap.messages_sent > 0);
    }
}
