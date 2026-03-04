
//! In-memory transport for consensus messages.
//!
//! This is intended for integration testing without sockets.
//! It simulates a small P2P network where nodes can broadcast `ConsensusMsg`
//! to all other registered nodes.

use crate::consensus::ConsensusMsg;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use tokio::sync::mpsc;

pub type NodeId = u64;

/// Handle used by a node to send messages into the in-memory network.
#[derive(Clone)]
pub struct InMemNet {
    inner: Arc<Mutex<Inner>>,
    pub node_id: NodeId,
}

struct Inner {
    peers: HashMap<NodeId, mpsc::UnboundedSender<ConsensusMsg>>,
}

impl InMemNet {
    /// Create a new network and register the first node.
    pub fn new(node_id: NodeId) -> (Self, mpsc::UnboundedReceiver<ConsensusMsg>) {
        let inner = Arc::new(Mutex::new(Inner { peers: HashMap::new() }));
        let (tx, rx) = mpsc::unbounded_channel();
        inner.lock().unwrap().peers.insert(node_id, tx);
        (Self { inner, node_id }, rx)
    }

    /// Register an additional node into the same network.
    pub fn register(&self, node_id: NodeId) -> mpsc::UnboundedReceiver<ConsensusMsg> {
        let (tx, rx) = mpsc::unbounded_channel();
        self.inner.lock().unwrap().peers.insert(node_id, tx);
        rx
    }


    /// Create another handle for the same underlying network but with a different local node id.
    pub fn handle(&self, node_id: NodeId) -> Self {
        Self { inner: self.inner.clone(), node_id }
    }

    /// Broadcast to all nodes except self.
    pub fn broadcast(&self, msg: ConsensusMsg) {
        let peers = self.inner.lock().unwrap().peers.clone();
        for (id, tx) in peers.into_iter() {
            if id == self.node_id { continue; }
            let _ = tx.send(msg.clone());
        }
    }
}
