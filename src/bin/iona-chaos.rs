//! Chaos harness (local).
//!
//! This is an executable (not just a test) meant to create adversarial-ish conditions:
//! - spawn N local nodes (iona-node) with random ports
//! - periodically kill/restart nodes
//! - periodically "partition" by restarting nodes with different static-peer sets
//!
//! NOTE: This is a pragmatic harness for regression testing. It is not a full network simulator.

use clap::Parser;
use rand::Rng;
use std::{
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    time::Duration,
};
use thiserror::Error;
use tokio::time::sleep;

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

// -----------------------------------------------------------------------------
// Errors
// -----------------------------------------------------------------------------

/// Errors that can occur during chaos test execution.
#[derive(Debug, Error)]
pub enum ChaosError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("failed to write config for node {node}: {source}")]
    ConfigWrite { node: usize, source: std::io::Error },

    #[error("failed to spawn node {node}: {source}")]
    Spawn { node: usize, source: std::io::Error },

    #[error("invalid probability: {0} (must be between 0.0 and 1.0)")]
    InvalidProbability(f64),
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
}

// -----------------------------------------------------------------------------
// Helper functions
// -----------------------------------------------------------------------------

/// Get the data directory for a specific node.
fn node_dir(base: &str, idx: usize) -> PathBuf {
    PathBuf::from(base).join(format!("node{}", idx))
}

/// Write the configuration file for a node.
fn write_config(
    dir: &Path,
    seed: u64,
    chain_id: u64,
    p2p_port: u16,
    rpc_port: u16,
    peers: &[String],
) -> ChaosResult<()> {
    std::fs::create_dir_all(dir).map_err(|e| ChaosError::ConfigWrite {
        node: seed as usize,
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
keystore_password_env = "IONA_KEYSTORE_PASSWORD"

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
        seed,
        chain_id,
        p2p_port,
        peers_toml,
        rpc_port,
    );

    std::fs::write(dir.join(CONFIG_FILE), cfg).map_err(|e| ChaosError::ConfigWrite {
        node: seed as usize,
        source: e,
    })?;
    Ok(())
}

/// Spawn a node process from its data directory.
fn spawn_node(dir: &Path, node_id: usize) -> ChaosResult<Child> {
    let mut cmd = Command::new("cargo");
    cmd.arg("run")
        .arg("--bin")
        .arg("iona-node")
        .arg("--")
        .arg("--config")
        .arg(dir.join(CONFIG_FILE));
    cmd.stdout(Stdio::inherit()).stderr(Stdio::inherit());
    cmd.spawn().map_err(|e| ChaosError::Spawn {
        node: node_id,
        source: e,
    })
}

/// Build the list of peer multiaddresses for a node (full mesh).
fn full_mesh_peers(node_idx: usize, nodes: usize, p2p_port_base: u16) -> Vec<String> {
    let mut peers = Vec::new();
    for j in 0..nodes {
        if node_idx == j {
            continue;
        }
        let port = p2p_port_base + j as u16;
        peers.push(format!("/ip4/127.0.0.1/tcp/{}", port));
    }
    peers
}

/// Kill a child process and wait for it to terminate.
fn kill_child(child: &mut Child) -> ChaosResult<()> {
    let _ = child.kill();
    let _ = child.wait();
    Ok(())
}

// -----------------------------------------------------------------------------
// Main
// -----------------------------------------------------------------------------

#[tokio::main]
async fn main() -> ChaosResult<()> {
    let args = Args::parse();

    // Validate probability.
    if !(0.0..=1.0).contains(&args.kill_prob) {
        return Err(ChaosError::InvalidProbability(args.kill_prob));
    }

    let mut children: Vec<Option<Child>> = (0..args.nodes).map(|_| None).collect();

    // Initial full‑mesh configuration and spawn.
    for i in 0..args.nodes {
        let peers = full_mesh_peers(i, args.nodes, args.p2p_port_base);
        let dir = node_dir(&args.data_dir, i + 1);
        write_config(
            &dir,
            (i + 1) as u64,
            CHAOS_CHAIN_ID,
            args.p2p_port_base + i as u16,
            args.rpc_port_base + i as u16,
            &peers,
        )?;
        children[i] = Some(spawn_node(&dir, i + 1)?);
    }

    let start = tokio::time::Instant::now();
    let mut rng = rand::thread_rng();
    let duration = Duration::from_secs(args.duration_s);
    let chaos_interval = Duration::from_secs(args.chaos_every_s.max(MIN_CHAOS_INTERVAL_S));

    while start.elapsed() < duration {
        sleep(chaos_interval).await;

        if rng.gen::<f64>() < args.kill_prob {
            // Kill and restart a random node.
            let idx = rng.gen_range(0..args.nodes);
            if let Some(mut child) = children[idx].take() {
                let _ = kill_child(&mut child);
            }
            let dir = node_dir(&args.data_dir, idx + 1);
            // Keep existing peers (no partition change).
            let peers = full_mesh_peers(idx, args.nodes, args.p2p_port_base);
            write_config(
                &dir,
                (idx + 1) as u64,
                CHAOS_CHAIN_ID,
                args.p2p_port_base + idx as u16,
                args.rpc_port_base + idx as u16,
                &peers,
            )?;
            children[idx] = Some(spawn_node(&dir, idx + 1)?);
            eprintln!("[chaos] restarted node{}", idx + 1);
        } else {
            // Partition shuffle: split nodes into two groups, reconfigure peers,
            // restart all nodes.
            let mut group_a = Vec::new();
            let mut group_b = Vec::new();
            for i in 0..args.nodes {
                if rng.gen::<bool>() {
                    group_a.push(i);
                } else {
                    group_b.push(i);
                }
            }

            if group_a.is_empty() || group_b.is_empty() {
                eprintln!("[chaos] partition shuffle skipped (one group empty)");
                continue;
            }

            // Kill all nodes.
            for i in 0..args.nodes {
                if let Some(mut child) = children[i].take() {
                    let _ = kill_child(&mut child);
                }
            }

            // Reconfigure nodes in group A.
            for &i in &group_a {
                let peers: Vec<String> = group_a
                    .iter()
                    .filter(|&&j| j != i)
                    .map(|&j| format!("/ip4/127.0.0.1/tcp/{}", args.p2p_port_base + j as u16))
                    .collect();
                let dir = node_dir(&args.data_dir, i + 1);
                write_config(
                    &dir,
                    (i + 1) as u64,
                    CHAOS_CHAIN_ID,
                    args.p2p_port_base + i as u16,
                    args.rpc_port_base + i as u16,
                    &peers,
                )?;
                children[i] = Some(spawn_node(&dir, i + 1)?);
            }

            // Reconfigure nodes in group B.
            for &i in &group_b {
                let peers: Vec<String> = group_b
                    .iter()
                    .filter(|&&j| j != i)
                    .map(|&j| format!("/ip4/127.0.0.1/tcp/{}", args.p2p_port_base + j as u16))
                    .collect();
                let dir = node_dir(&args.data_dir, i + 1);
                write_config(
                    &dir,
                    (i + 1) as u64,
                    CHAOS_CHAIN_ID,
                    args.p2p_port_base + i as u16,
                    args.rpc_port_base + i as u16,
                    &peers,
                )?;
                children[i] = Some(spawn_node(&dir, i + 1)?);
            }

            eprintln!(
                "[chaos] applied partition shuffle: A={} B={}",
                group_a.len(),
                group_b.len()
            );
        }
    }

    // Clean up all nodes.
    for i in 0..args.nodes {
        if let Some(mut child) = children[i].take() {
            let _ = kill_child(&mut child);
        }
    }

    eprintln!("[chaos] test completed");
    Ok(())
}
