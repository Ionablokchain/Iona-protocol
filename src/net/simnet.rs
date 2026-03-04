//! In-memory simnet transport for integration testing.
//!
//! This simnet can deliver:
//! - consensus broadcasts (e.g. Proposal/Vote)
//! - block request/response used when proposals arrive without full blocks
//!
//! PRO++++ additions:
//! - deterministic packet loss (drop) and delay simulation
//! - bounded consensus history + replay to late joiners

use crate::consensus::ConsensusMsg;
use crate::types::{Block, Hash32};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use tokio::sync::mpsc;

pub type NodeId = u64;

#[derive(Clone, Debug)]
pub enum NetMsg {
    Consensus { from: NodeId, msg: ConsensusMsg },
    BlockRequest { from: NodeId, id: Hash32 },
    BlockResponse { from: NodeId, block: Block },
}

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
        }
    }
}

/// Handle used by a node to interact with the simnet.
#[derive(Clone)]
pub struct SimNet {
    inner: Arc<Mutex<Inner>>,
    pub node_id: NodeId,
}

struct Inner {
    peers: HashMap<NodeId, mpsc::UnboundedSender<NetMsg>>,
    cfg: SimNetConfig,
    rng: u64,
    consensus_history: Vec<ConsensusMsg>,
    partitions: HashMap<NodeId, u64>,
    partitioning_enabled: bool,
}

impl SimNet {
    pub fn new(node_id: NodeId) -> (Self, mpsc::UnboundedReceiver<NetMsg>) {
        Self::with_config(node_id, SimNetConfig::default())
    }

    pub fn with_config(node_id: NodeId, cfg: SimNetConfig) -> (Self, mpsc::UnboundedReceiver<NetMsg>) {
        let inner = Arc::new(Mutex::new(Inner {
            peers: HashMap::new(),
            rng: cfg.seed ^ (node_id.wrapping_mul(0x9E37_79B9_7F4A_7C15)),
            consensus_history: Vec::new(),
            partitions: HashMap::new(),
            partitioning_enabled: false,
            cfg,
        }));
        let (tx, rx) = mpsc::unbounded_channel();
        let mut g = inner.lock().unwrap();
        g.peers.insert(node_id, tx);
        g.partitions.insert(node_id, 0);
        drop(g);
        (Self { inner, node_id }, rx)
    }

    pub fn register(&self, node_id: NodeId) -> mpsc::UnboundedReceiver<NetMsg> {
        let (tx, rx) = mpsc::unbounded_channel();
        let mut g = self.inner.lock().unwrap();
        g.peers.insert(node_id, tx);
        g.partitions.insert(node_id, 0);
        drop(g);
        rx
    }


    /// Enable partitioning (messages across different partitions are dropped).
    pub fn enable_partitioning(&self, enabled: bool) {
        if let Ok(mut g) = self.inner.lock() {
            g.partitioning_enabled = enabled;
        }
    }

    /// Assign a node to a partition id (0 by default).
    pub fn set_partition(&self, node_id: NodeId, partition_id: u64) {
        if let Ok(mut g) = self.inner.lock() {
            g.partitions.insert(node_id, partition_id);
        }
    }

    /// Snapshot of bounded consensus history (for tests/diagnostics).
    pub fn consensus_history(&self) -> Vec<ConsensusMsg> {
        self.inner.lock().map(|g| g.consensus_history.clone()).unwrap_or_default()
    }

    pub fn handle(&self, node_id: NodeId) -> Self {
        Self { inner: self.inner.clone(), node_id }
    }

    /// Replay bounded consensus history to a given node (useful for late joiners).
    pub fn replay_consensus_to(&self, to: NodeId) {
        let (tx, msgs, delay_cfg, drop_ppm, from) = {
            let inner = self.inner.lock().unwrap();
            let tx = match inner.peers.get(&to) {
                Some(t) => t.clone(),
                None => return,
            };
            (tx, inner.consensus_history.clone(), inner.cfg.clone(), inner.cfg.drop_ppm_consensus, self.node_id)
        };
        for msg in msgs {
            Self::send_with_impairments(tx.clone(), delay_cfg.clone(), drop_ppm, NetMsg::Consensus { from, msg });
        }
    }

    pub fn send_to(&self, to: NodeId, msg: NetMsg) {
        let (tx, cfg, drop_ppm, allow) = {
            let inner = self.inner.lock().unwrap();
            let tx = match inner.peers.get(&to) { Some(t) => t.clone(), None => return };
            let drop_ppm = match msg {
                NetMsg::Consensus { .. } => inner.cfg.drop_ppm_consensus,
                NetMsg::BlockRequest { .. } | NetMsg::BlockResponse { .. } => inner.cfg.drop_ppm_block,
            };
            let allow = if inner.partitioning_enabled {
                let a = *inner.partitions.get(&self.node_id).unwrap_or(&0);
                let b = *inner.partitions.get(&to).unwrap_or(&0);
                a == b
            } else { true };
            (tx, inner.cfg.clone(), drop_ppm, allow)
        };
        if !allow { return; }
        Self::send_with_impairments(tx, cfg, drop_ppm, msg);
    }

    pub fn broadcast_consensus(&self, msg: ConsensusMsg) {
        let (peers, cfg, drop_ppm, from, _history, cfg_partitioning, partitions, my_part) = {
            let mut inner = self.inner.lock().unwrap();

            // update bounded history
            inner.consensus_history.push(msg.clone());
            if inner.consensus_history.len() > inner.cfg.history_limit {
                let extra = inner.consensus_history.len() - inner.cfg.history_limit;
                inner.consensus_history.drain(0..extra);
            }

            (inner.peers.clone(), inner.cfg.clone(), inner.cfg.drop_ppm_consensus, self.node_id,
             inner.consensus_history.clone(), inner.partitioning_enabled, inner.partitions.clone(), inner.partitions.get(&self.node_id).copied().unwrap_or(0))
        };

        // broadcast to all except self
        for (id, tx) in peers.into_iter() {
            if id == self.node_id { continue; }
            // partition filter
            if cfg_partitioning && partitions.get(&id).copied().unwrap_or(0) != my_part { continue; }
            Self::send_with_impairments(tx, cfg.clone(), drop_ppm, NetMsg::Consensus { from, msg: msg.clone() });
        }
    }

    pub fn request_block(&self, id: Hash32) {
        let (peers, cfg, drop_ppm, from, cfg_partitioning, partitions, my_part) = {
            let inner = self.inner.lock().unwrap();
            (inner.peers.clone(), inner.cfg.clone(), inner.cfg.drop_ppm_block, self.node_id,
             inner.partitioning_enabled, inner.partitions.clone(), inner.partitions.get(&self.node_id).copied().unwrap_or(0))
        };
        for (pid, tx) in peers.into_iter() {
            if pid == self.node_id { continue; }
            if cfg_partitioning && partitions.get(&pid).copied().unwrap_or(0) != my_part { continue; }
            Self::send_with_impairments(tx, cfg.clone(), drop_ppm, NetMsg::BlockRequest { from, id: id.clone() });
        }
    }

    fn rand_u32(inner: &mut Inner) -> u32 {
        // xorshift64*
        let mut x = inner.rng;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        inner.rng = x;
        ((x.wrapping_mul(0x2545F4914F6CDD1D) >> 32) & 0xFFFF_FFFF) as u32
    }

    fn should_drop(inner: &mut Inner, drop_ppm: u32) -> bool {
        if drop_ppm == 0 { return false; }
        let r = Self::rand_u32(inner) % 1_000_000;
        r < drop_ppm
    }

    fn sample_delay_ms(inner: &mut Inner) -> u64 {
        let min = inner.cfg.min_delay_ms;
        let max = inner.cfg.max_delay_ms;
        if max <= min { return min; }
        let span = max - min + 1;
        let r = (Self::rand_u32(inner) as u64) % span;
        min + r
    }

    fn send_with_impairments(tx: mpsc::UnboundedSender<NetMsg>, cfg: SimNetConfig, drop_ppm: u32, msg: NetMsg) {
        // impairment decisions are centralized under the Inner mutex to keep determinism
        let (drop_it, delay_ms) = {
            // create a temporary inner-like RNG state for this send by hashing (deterministic but not shared)
            // Note: we still keep determinism across runs; we don't require strict global ordering determinism.
            // For tests that need strict determinism, prefer using `replay_consensus_to` retry loops.
            let mut x = cfg.seed ^ 0xA5A5_A5A5_A5A5_A5A5;
            // small mix from msg discriminant
            x ^= match msg {
                NetMsg::Consensus { .. } => 1,
                NetMsg::BlockRequest { .. } => 2,
                NetMsg::BlockResponse { .. } => 3,
            };
            // xorshift
            x ^= x >> 12; x ^= x << 25; x ^= x >> 27;
            let r = ((x.wrapping_mul(0x2545F4914F6CDD1D) >> 32) & 0xFFFF_FFFF) as u32;
            let drop_it = drop_ppm != 0 && (r % 1_000_000) < drop_ppm;
            let delay_ms = if cfg.max_delay_ms <= cfg.min_delay_ms { cfg.min_delay_ms } else {
                let span = cfg.max_delay_ms - cfg.min_delay_ms + 1;
                cfg.min_delay_ms + (r as u64 % span)
            };
            (drop_it, delay_ms)
        };

        if drop_it { return; }
        if delay_ms == 0 {
            let _ = tx.send(msg);
            return;
        }
        tokio::spawn(async move {
            tokio::time::sleep(std::time::Duration::from_millis(delay_ms)).await;
            let _ = tx.send(msg);
        });
    }

    /// Request a block with simple retry + backoff.
    /// This is intended for tests that simulate loss on block traffic.
    pub fn request_block_with_retry(&self, id: Hash32, attempts: u32, base_delay_ms: u64) {
        let net = self.clone();
        tokio::spawn(async move {
            let mut delay = base_delay_ms;
            for _ in 0..attempts {
                net.request_block(id.clone());
                tokio::time::sleep(std::time::Duration::from_millis(delay)).await;
                delay = (delay.saturating_mul(2)).min(200);
            }
        });
    }

}
