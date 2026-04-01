//! Chaos harness (local).
//!
//! This is an executable (not just a test) meant to create adversarial‑ish conditions:
//! - spawn N local nodes (iona-node) with random ports
//! - periodically kill/restart nodes
//! - periodically "partition" by restarting nodes with different static‑peer sets
//!
//! NOTE: This is a pragmatic harness for regression testing. It is not a full network simulator.
//!
//! # Usage
//!
//! ```bash
//! cargo run --bin iona-chaos -- --nodes 6 --duration-s 120
//! ```

use clap::Parser;
use rand::Rng;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::Duration;
use tokio::time::sleep;
use tracing::{error, info, warn};

// -----------------------------------------------------------------------------
// Command-line arguments
// -----------------------------------------------------------------------------

#[derive(Parser, Debug)]
#[command(name = "iona-chaos", about = "IONA chaos harness (local multi‑node)")]
struct Args {
    /// Number of nodes to spawn.
    #[arg(long, default_value_t = 6)]
    nodes: usize,

    /// Base data directory (subdirs node1..nodeN are created).
    #[arg(long, default_value = "./data/chaos")]
    data_dir: String,

    /// Base TCP port for P2P (each node gets base + i).
    #[arg(long, default_value_t = 17001)]
    p2p_port_base: u16,

    /// Base port for RPC (each node gets base + i).
    #[arg(long, default_value_t = 19001)]
    rpc_port_base: u16,

    /// Test duration in seconds.
    #[arg(long, default_value_t = 120)]
    duration_s: u64,

    /// Average seconds between chaos actions.
    #[arg(long, default_value_t = 10)]
    chaos_every_s: u64,

    /// Probability [0..1] of a kill/restart action (else partition shuffle).
    #[arg(long, default_value_t = 0.6)]
    kill_prob: f64,

    /// Chain ID to use in node configurations.
    #[arg(long, default_value_t = 7777)]
    chain_id: u64,

    /// Log level (trace, debug, info, warn, error). Default is info.
    #[arg(long, default_value = "info")]
    log_level: String,
}

// -----------------------------------------------------------------------------
// Helper functions
// -----------------------------------------------------------------------------

/// Construct the data directory path for a given node index.
fn node_dir(base: &str, idx: usize) -> PathBuf {
    PathBuf::from(base).join(format!("node{}", idx))
}

/// Write a node configuration file.
fn write_config(
    dir: &Path,
    seed: u64,
    chain_id: u64,
    p2p_port: u16,
    rpc_port: u16,
    peers: Vec<String>,
) -> anyhow::Result<()> {
    std::fs::create_dir_all(dir)?;
    let peers_str = peers
        .into_iter()
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
        peers_str,
        rpc_port,
    );
    std::fs::write(dir.join("config.toml"), cfg)?;
    Ok(())
}

/// Spawn an `iona-node` process with the given configuration directory.
fn spawn_node(dir: &Path) -> anyhow::Result<Child> {
    let mut cmd = Command::new("cargo");
    cmd.arg("run")
        .arg("--bin")
        .arg("iona-node")
        .arg("--")
        .arg("--config")
        .arg(dir.join("config.toml"));
    cmd.stdout(Stdio::inherit()).stderr(Stdio::inherit());
    Ok(cmd.spawn()?)
}

/// Kill a child process and wait for it to exit.
fn kill_node(child: &mut Option<Child>) {
    if let Some(mut ch) = child.take() {
        if let Err(e) = ch.kill() {
            warn!("failed to kill node: {}", e);
        }
        if let Err(e) = ch.wait() {
            warn!("failed to wait for node exit: {}", e);
        }
    }
}

// -----------------------------------------------------------------------------
// Main
// -----------------------------------------------------------------------------

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = Args::parse();

    // Initialise logging.
    init_logging(&args.log_level)?;
    info!("Starting IONA chaos harness (version {})", env!("CARGO_PKG_VERSION"));

    let mut children: Vec<Option<Child>> = (0..args.nodes).map(|_| None).collect();

    // Initial full‑mesh peers configuration.
    for i in 0..args.nodes {
        let mut peers = Vec::new();
        for j in 0..args.nodes {
            if i == j {
                continue;
            }
            let port = args.p2p_port_base + j as u16;
            peers.push(format!("/ip4/127.0.0.1/tcp/{}", port));
        }
        let dir = node_dir(&args.data_dir, i + 1);
        write_config(
            &dir,
            (i + 1) as u64,
            args.chain_id,
            args.p2p_port_base + i as u16,
            args.rpc_port_base + i as u16,
            peers,
        )?;
        children[i] = Some(spawn_node(&dir)?);
    }

    info!("All nodes started (full mesh).");

    let start = tokio::time::Instant::now();
    let mut rng = rand::thread_rng();

    // Main chaos loop.
    while start.elapsed() < Duration::from_secs(args.duration_s) {
        let sleep_dur = Duration::from_secs(args.chaos_every_s.max(1));
        sleep(sleep_dur).await;

        if rng.gen::<f64>() < args.kill_prob {
            // Kill and restart a random node.
            let idx = rng.gen_range(0..args.nodes);
            kill_node(&mut children[idx]);

            let dir = node_dir(&args.data_dir, idx + 1);
            children[idx] = Some(spawn_node(&dir)?);
            info!("[chaos] restarted node{}", idx + 1);
        } else {
            // Partition shuffle: split nodes into two groups and re‑wire peers.
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
                continue;
            }

            // Kill all nodes first.
            for i in 0..args.nodes {
                kill_node(&mut children[i]);
            }

            // Re‑configure and restart group A.
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
                    args.chain_id,
                    args.p2p_port_base + i as u16,
                    args.rpc_port_base + i as u16,
                    peers,
                )?;
                children[i] = Some(spawn_node(&dir)?);
            }

            // Re‑configure and restart group B.
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
                    args.chain_id,
                    args.p2p_port_base + i as u16,
                    args.rpc_port_base + i as u16,
                    peers,
                )?;
                children[i] = Some(spawn_node(&dir)?);
            }

            info!(
                "[chaos] applied partition shuffle: A={} nodes, B={} nodes",
                group_a.len(),
                group_b.len()
            );
        }
    }

    // Clean up all nodes.
    info!("Test duration finished. Shutting down nodes.");
    for i in 0..args.nodes {
        kill_node(&mut children[i]);
    }

    info!("Chaos harness completed.");
    Ok(())
}

// -----------------------------------------------------------------------------
// Logging initialisation
// -----------------------------------------------------------------------------

fn init_logging(level: &str) -> anyhow::Result<()> {
    use tracing_subscriber::{fmt, prelude::*, EnvFilter};

    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new(level));

    let subscriber = fmt::Subscriber::builder()
        .json()
        .with_target(true)
        .with_thread_ids(false)
        .with_env_filter(filter)
        .finish();

    tracing::subscriber::set_global_default(subscriber)?;
    Ok(())
}
