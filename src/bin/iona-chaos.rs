//! Chaos harness (local multi‑node) for IONA.
//!
//! This executable creates adversarial conditions:
//! - spawn N local nodes (`iona-node`) with random ports
//! - periodically kill/restart nodes
//! - periodically “partition” the network by restarting nodes with different static‑peer sets
//!
//! # Usage
//!
//! ```bash
//! cargo run --bin iona-chaos -- --nodes 6 --duration 120 --chaos-every 10
//! ```
//!
//! # Graceful shutdown
//! Press Ctrl+C to stop the test; all child processes will be terminated.

use clap::Parser;
use rand::Rng;
use std::collections::{BTreeMap, HashSet};
use std::fs::{self, File};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use thiserror::Error;
use tokio::signal;
use tokio::time::sleep;
use tracing::{debug, error, info, warn};
use tracing_subscriber::EnvFilter;

// -----------------------------------------------------------------------------
// Constants
// -----------------------------------------------------------------------------

/// Default number of nodes.
const DEFAULT_NODES: usize = 6;

/// Default base data directory.
const DEFAULT_DATA_DIR: &str = "./data/chaos";

/// Default base P2P port.
const DEFAULT_P2P_PORT_BASE: u16 = 17001;

/// Default base RPC port.
const DEFAULT_RPC_PORT_BASE: u16 = 19001;

/// Default test duration in seconds.
const DEFAULT_DURATION_S: u64 = 120;

/// Default interval between chaos actions (seconds).
const DEFAULT_CHAOS_EVERY_S: u64 = 10;

/// Default probability of kill/restart action (vs partition shuffle).
const DEFAULT_KILL_PROB: f64 = 0.6;

/// Chain ID used for the chaos testnet.
const CHAOS_CHAIN_ID: u64 = 7777;

/// Config file name.
const CONFIG_FILE: &str = "config.toml";

/// Minimum chaos interval (seconds).
const MIN_CHAOS_INTERVAL_S: u64 = 1;

/// Default health check interval (seconds).
const DEFAULT_HEALTH_CHECK_INTERVAL_S: u64 = 5;

/// Default maximum restarts per node.
const DEFAULT_MAX_RESTARTS: usize = 10;

// -----------------------------------------------------------------------------
// Errors
// -----------------------------------------------------------------------------

/// Errors that can occur during chaos test execution.
#[derive(Debug, Error)]
pub enum ChaosError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("failed to write config for node {node}: {source}")]
    ConfigWrite {
        node: usize,
        source: std::io::Error,
    },

    #[error("failed to spawn node {node}: {source}")]
    Spawn {
        node: usize,
        source: std::io::Error,
    },

    #[error("failed to kill node {node}: {source}")]
    Kill {
        node: usize,
        source: std::io::Error,
    },

    #[error("node {node} died unexpectedly")]
    NodeDied { node: usize },

    #[error("invalid probability: {0} (must be between 0.0 and 1.0)")]
    InvalidProbability(f64),

    #[error("max restarts exceeded for node {node} (limit {max})")]
    MaxRestartsExceeded { node: usize, max: usize },

    #[error("timeout waiting for node {node} to start")]
    StartTimeout { node: usize },

    #[error("channel error: {0}")]
    Channel(#[from] tokio::sync::mpsc::error::SendError<()>),
}

pub type ChaosResult<T> = Result<T, ChaosError>;

// -----------------------------------------------------------------------------
// CLI Arguments
// -----------------------------------------------------------------------------

#[derive(Parser, Debug)]
#[command(name = "iona-chaos")]
#[command(about = "IONA chaos harness (local multi-node)", long_about = None)]
struct Args {
    /// Number of nodes to spawn.
    #[arg(long, default_value_t = DEFAULT_NODES)]
    nodes: usize,

    /// Base data directory (subdirs node1..nodeN are created).
    #[arg(long, default_value = DEFAULT_DATA_DIR)]
    data_dir: String,

    /// Base TCP port for P2P (each node gets base + i).
    #[arg(long, default_value_t = DEFAULT_P2P_PORT_BASE)]
    p2p_port_base: u16,

    /// Base port for RPC (each node gets base + i).
    #[arg(long, default_value_t = DEFAULT_RPC_PORT_BASE)]
    rpc_port_base: u16,

    /// Test duration in seconds.
    #[arg(long, default_value_t = DEFAULT_DURATION_S)]
    duration_s: u64,

    /// Average seconds between chaos actions.
    #[arg(long, default_value_t = DEFAULT_CHAOS_EVERY_S)]
    chaos_every_s: u64,

    /// Probability [0..1] of a kill/restart action (otherwise partition shuffle).
    #[arg(long, default_value_t = DEFAULT_KILL_PROB)]
    kill_prob: f64,

    /// Maximum restarts per node (0 = unlimited).
    #[arg(long, default_value_t = DEFAULT_MAX_RESTARTS)]
    max_restarts: usize,

    /// Health check interval in seconds.
    #[arg(long, default_value_t = DEFAULT_HEALTH_CHECK_INTERVAL_S)]
    health_check_interval_s: u64,

    /// Do not respawn crashed nodes (only log).
    #[arg(long, default_value_t = false)]
    no_respawn: bool,

    /// Verbose output.
    #[arg(long, default_value_t = false)]
    verbose: bool,

    /// Quiet output (only errors).
    #[arg(long, default_value_t = false)]
    quiet: bool,
}

// -----------------------------------------------------------------------------
// Node handle
// -----------------------------------------------------------------------------

/// A running node process with its metadata.
struct NodeHandle {
    id: usize,
    child: Child,
    data_dir: PathBuf,
    p2p_port: u16,
    rpc_port: u16,
    restarts: usize,
}

impl NodeHandle {
    fn kill(&mut self) -> ChaosResult<()> {
        self.child
            .kill()
            .map_err(|e| ChaosError::Kill {
                node: self.id,
                source: e,
            })?;
        let _ = self.child.wait();
        Ok(())
    }

    fn is_alive(&mut self) -> bool {
        match self.child.try_wait() {
            Ok(None) => true,
            Ok(Some(_)) => false,
            Err(_) => false,
        }
    }
}

// -----------------------------------------------------------------------------
// Chaos orchestrator
// -----------------------------------------------------------------------------

struct ChaosOrchestrator {
    nodes: Vec<Option<NodeHandle>>,
    args: Args,
    rng: rand::rngs::ThreadRng,
    start_time: Instant,
    shutdown: Arc<AtomicBool>,
}

impl ChaosOrchestrator {
    fn new(args: Args) -> Self {
        Self {
            nodes: vec![None; args.nodes],
            args,
            rng: rand::thread_rng(),
            start_time: Instant::now(),
            shutdown: Arc::new(AtomicBool::new(false)),
        }
    }

    /// Build the list of peer multiaddresses for a node (full mesh).
    fn full_mesh_peers(&self, node_idx: usize) -> Vec<String> {
        let mut peers = Vec::new();
        for j in 0..self.args.nodes {
            if node_idx == j {
                continue;
            }
            let port = self.args.p2p_port_base + j as u16;
            peers.push(format!("/ip4/127.0.0.1/tcp/{}", port));
        }
        peers
    }

    /// Write configuration file for a node.
    fn write_config(&self, node_idx: usize, peers: &[String]) -> ChaosResult<()> {
        let dir = node_dir(&self.args.data_dir, node_idx + 1);
        std::fs::create_dir_all(&dir).map_err(|e| ChaosError::ConfigWrite {
            node: node_idx + 1,
            source: e,
        })?;

        let peers_toml = peers
            .iter()
            .map(|p| format!("  \"{}\",", p))
            .collect::<Vec<_>>()
            .join("\n");

        let cfg = format!(
            r#"[node]
data_dir = "{}"
seed = {}
chain_id = {}
log_level = "info"
keystore = "plain"

[network]
listen = "/ip4/127.0.0.1/tcp/{}"
peers = [
{}
]
bootnodes = []
enable_mdns = false
enable_kad = false
reconnect_s = 2

[rpc]
listen = "127.0.0.1:{}"
enable_faucet = false
"#,
            dir.to_string_lossy(),
            (node_idx + 1) as u64,
            CHAOS_CHAIN_ID,
            self.args.p2p_port_base + node_idx as u16,
            peers_toml,
            self.args.rpc_port_base + node_idx as u16,
        );

        std::fs::write(dir.join(CONFIG_FILE), cfg).map_err(|e| ChaosError::ConfigWrite {
            node: node_idx + 1,
            source: e,
        })?;
        Ok(())
    }

    /// Spawn a node process.
    async fn spawn_node(&mut self, node_idx: usize) -> ChaosResult<()> {
        let dir = node_dir(&self.args.data_dir, node_idx + 1);
        let mut cmd = Command::new("cargo");
        cmd.arg("run")
            .arg("--bin")
            .arg("iona-node")
            .arg("--")
            .arg("--config")
            .arg(dir.join(CONFIG_FILE));
        cmd.stdout(Stdio::inherit()).stderr(Stdio::inherit());

        let child = cmd.spawn().map_err(|e| ChaosError::Spawn {
            node: node_idx + 1,
            source: e,
        })?;

        // Wait a bit for the node to start (simple health check)
        sleep(Duration::from_secs(1)).await;

        let node = NodeHandle {
            id: node_idx + 1,
            child,
            data_dir: dir,
            p2p_port: self.args.p2p_port_base + node_idx as u16,
            rpc_port: self.args.rpc_port_base + node_idx as u16,
            restarts: 0,
        };
        self.nodes[node_idx] = Some(node);
        Ok(())
    }

    /// Kill a node and remove its handle.
    async fn kill_node(&mut self, node_idx: usize) -> ChaosResult<()> {
        if let Some(mut node) = self.nodes[node_idx].take() {
            node.kill()?;
            info!("Node {} killed", node.id);
        }
        Ok(())
    }

    /// Restart a node (kill, reconfigure, spawn).
    async fn restart_node(&mut self, node_idx: usize, peers: &[String]) -> ChaosResult<()> {
        self.kill_node(node_idx).await?;
        self.write_config(node_idx, peers)?;
        self.spawn_node(node_idx).await?;
        if let Some(ref mut node) = self.nodes[node_idx] {
            node.restarts += 1;
            info!("Node {} restarted (restart count: {})", node.id, node.restarts);
        }
        Ok(())
    }

    /// Check health of all nodes and respawn dead ones if allowed.
    async fn health_check(&mut self) -> ChaosResult<()> {
        for i in 0..self.args.nodes {
            if let Some(ref mut node) = self.nodes[i] {
                if !node.is_alive() {
                    warn!("Node {} died unexpectedly", node.id);
                    if self.args.no_respawn {
                        warn!("Respawn disabled, node {} remains dead", node.id);
                        self.nodes[i] = None;
                    } else {
                        let new_restarts = node.restarts + 1;
                        if self.args.max_restarts > 0 && new_restarts > self.args.max_restarts {
                            error!("Node {} exceeded max restarts ({}), giving up", node.id, self.args.max_restarts);
                            self.nodes[i] = None;
                        } else {
                            info!("Respawning node {}", node.id);
                            let peers = self.full_mesh_peers(i);
                            self.restart_node(i, &peers).await?;
                        }
                    }
                }
            }
        }
        Ok(())
    }

    /// Perform a chaos action: either kill/restart a random node or partition shuffle.
    async fn chaos_action(&mut self) -> ChaosResult<()> {
        if self.rng.gen::<f64>() < self.args.kill_prob {
            // Kill and restart a random node.
            let idx = self.rng.gen_range(0..self.args.nodes);
            if self.nodes[idx].is_some() {
                let peers = self.full_mesh_peers(idx);
                self.restart_node(idx, &peers).await?;
                info!("Chaos: restarted node {}", idx + 1);
            } else {
                debug!("Node {} is dead, skipping kill action", idx + 1);
            }
        } else {
            // Partition shuffle: split nodes into two groups.
            let mut group_a = Vec::new();
            let mut group_b = Vec::new();
            for i in 0..self.args.nodes {
                if self.rng.gen::<bool>() {
                    group_a.push(i);
                } else {
                    group_b.push(i);
                }
            }

            if group_a.is_empty() || group_b.is_empty() {
                debug!("Partition shuffle skipped (one group empty)");
                return Ok(());
            }

            info!("Chaos: applying partition shuffle: A={:?} B={:?}", group_a, group_b);

            // Kill all nodes first.
            for i in 0..self.args.nodes {
                self.kill_node(i).await?;
            }

            // Reconfigure group A.
            for &i in &group_a {
                let peers: Vec<String> = group_a
                    .iter()
                    .filter(|&&j| j != i)
                    .map(|&j| format!("/ip4/127.0.0.1/tcp/{}", self.args.p2p_port_base + j as u16))
                    .collect();
                self.write_config(i, &peers)?;
                self.spawn_node(i).await?;
            }

            // Reconfigure group B.
            for &i in &group_b {
                let peers: Vec<String> = group_b
                    .iter()
                    .filter(|&&j| j != i)
                    .map(|&j| format!("/ip4/127.0.0.1/tcp/{}", self.args.p2p_port_base + j as u16))
                    .collect();
                self.write_config(i, &peers)?;
                self.spawn_node(i).await?;
            }
            info!("Chaos: partition shuffle completed");
        }
        Ok(())
    }

    /// Run the main loop.
    async fn run(mut self) -> ChaosResult<()> {
        // Initialise all nodes.
        info!("Creating configuration and spawning {} nodes...", self.args.nodes);
        for i in 0..self.args.nodes {
            let peers = self.full_mesh_peers(i);
            self.write_config(i, &peers)?;
            self.spawn_node(i).await?;
        }
        info!("All nodes started.");

        let duration = Duration::from_secs(self.args.duration_s);
        let chaos_interval = Duration::from_secs(self.args.chaos_every_s.max(MIN_CHAOS_INTERVAL_S));
        let health_check_interval = Duration::from_secs(self.args.health_check_interval_s);

        let shutdown = self.shutdown.clone();
        let mut chaos_ticker = tokio::time::interval(chaos_interval);
        let mut health_ticker = tokio::time::interval(health_check_interval);
        chaos_ticker.tick().await; // skip immediate tick

        let mut last_print = Instant::now();

        loop {
            tokio::select! {
                _ = chaos_ticker.tick() => {
                    if self.start_time.elapsed() >= duration {
                        break;
                    }
                    if let Err(e) = self.chaos_action().await {
                        error!("Chaos action failed: {}", e);
                    }
                }
                _ = health_ticker.tick() => {
                    if let Err(e) = self.health_check().await {
                        error!("Health check failed: {}", e);
                    }
                }
                _ = tokio::time::sleep(Duration::from_millis(100)) => {
                    // progress report every 10 seconds
                    if last_print.elapsed() >= Duration::from_secs(10) {
                        let elapsed = self.start_time.elapsed().as_secs();
                        info!("Progress: {}/{} seconds, nodes alive: {}",
                            elapsed, self.args.duration_s,
                            self.nodes.iter().filter(|n| n.is_some()).count());
                        last_print = Instant::now();
                    }
                }
                _ = signal::ctrl_c() => {
                    info!("Received SIGINT, shutting down gracefully...");
                    shutdown.store(true, Ordering::SeqCst);
                    break;
                }
            }
            if shutdown.load(Ordering::SeqCst) {
                break;
            }
        }

        info!("Test finished. Terminating all nodes...");
        for i in 0..self.args.nodes {
            let _ = self.kill_node(i).await;
        }
        info!("Chaos test completed.");
        Ok(())
    }
}

// -----------------------------------------------------------------------------
// Helper functions
// -----------------------------------------------------------------------------

/// Get the data directory for a specific node.
fn node_dir(base: &str, idx: usize) -> PathBuf {
    PathBuf::from(base).join(format!("node{}", idx))
}

// -----------------------------------------------------------------------------
// Initialisation
// -----------------------------------------------------------------------------

fn init_tracing(verbose: bool, quiet: bool) {
    let filter = if verbose {
        "iona_chaos=debug,info"
    } else if quiet {
        "iona_chaos=error"
    } else {
        "iona_chaos=info"
    };
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::new(filter))
        .with_target(false)
        .init();
}

// -----------------------------------------------------------------------------
// Main
// -----------------------------------------------------------------------------

#[tokio::main]
async fn main() -> ChaosResult<()> {
    let args = Args::parse();

    if args.kill_prob < 0.0 || args.kill_prob > 1.0 {
        return Err(ChaosError::InvalidProbability(args.kill_prob));
    }

    init_tracing(args.verbose, args.quiet);

    info!("Starting IONA chaos test with {} nodes", args.nodes);
    info!("Duration: {} seconds, chaos every {} seconds, kill prob: {}",
        args.duration_s, args.chaos_every_s, args.kill_prob);

    let orchestrator = ChaosOrchestrator::new(args);
    orchestrator.run().await
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_full_mesh_peers() {
        let args = Args {
            nodes: 3,
            p2p_port_base: 10000,
            ..Default::default()
        };
        let orch = ChaosOrchestrator::new(args);
        let peers = orch.full_mesh_peers(0);
        assert_eq!(peers.len(), 2);
        assert!(peers.contains(&"/ip4/127.0.0.1/tcp/10001".to_string()));
        assert!(peers.contains(&"/ip4/127.0.0.1/tcp/10002".to_string()));
    }

    #[test]
    fn test_node_dir() {
        let dir = node_dir("/tmp/chaos", 5);
        assert_eq!(dir.to_str().unwrap(), "/tmp/chaos/node5");
    }
}
