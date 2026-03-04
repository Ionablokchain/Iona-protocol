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
use std::{path::PathBuf, process::{Child, Command, Stdio}, time::Duration};
use tokio::time::sleep;

#[derive(Parser, Debug)]
#[command(name="iona-chaos", about="IONA chaos harness (local multi-node)")]
struct Args {
    /// Number of nodes to spawn
    #[arg(long, default_value_t = 6)]
    nodes: usize,

    /// Base data dir (subdirs node1..nodeN are created)
    #[arg(long, default_value = "./data/chaos")]
    data_dir: String,

    /// Base TCP port for p2p (each node gets base+i)
    #[arg(long, default_value_t = 17001)]
    p2p_port_base: u16,

    /// Base port for RPC (each node gets base+i)
    #[arg(long, default_value_t = 19001)]
    rpc_port_base: u16,

    /// Test duration in seconds
    #[arg(long, default_value_t = 120)]
    duration_s: u64,

    /// Average seconds between chaos actions
    #[arg(long, default_value_t = 10)]
    chaos_every_s: u64,

    /// Probability [0..1] of a kill/restart action (else partition shuffle)
    #[arg(long, default_value_t = 0.6)]
    kill_prob: f64,
}

fn node_dir(base: &str, idx: usize) -> PathBuf {
    PathBuf::from(base).join(format!("node{}", idx))
}

fn write_config(dir: &PathBuf, seed: u64, chain_id: u64, p2p_port: u16, rpc_port: u16, peers: Vec<String>) -> anyhow::Result<()> {
    std::fs::create_dir_all(dir)?;
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
        peers.into_iter().map(|p| format!("  \"{}\",", p)).collect::<Vec<_>>().join("\n"),
        rpc_port,
    );
    std::fs::write(dir.join("config.toml"), cfg)?;
    Ok(())
}

fn spawn_node(dir: &PathBuf) -> anyhow::Result<Child> {
    let mut cmd = Command::new("cargo");
    cmd.arg("run").arg("--bin").arg("iona-node").arg("--").arg("--config").arg(dir.join("config.toml"));
    cmd.stdout(Stdio::inherit()).stderr(Stdio::inherit());
    Ok(cmd.spawn()?)
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = Args::parse();

    let chain_id = 7777u64;
    let mut children: Vec<Option<Child>> = (0..args.nodes).map(|_| None).collect();

    // initial full-mesh peers
    for i in 0..args.nodes {
        let mut peers = vec![];
        for j in 0..args.nodes {
            if i == j { continue; }
            let port = args.p2p_port_base + j as u16;
            peers.push(format!("/ip4/127.0.0.1/tcp/{}", port));
        }
        let dir = node_dir(&args.data_dir, i+1);
        write_config(&dir, (i+1) as u64, chain_id, args.p2p_port_base + i as u16, args.rpc_port_base + i as u16, peers)?;
        children[i] = Some(spawn_node(&dir)?);
    }

    let start = tokio::time::Instant::now();
    let mut rng = rand::thread_rng();

    while start.elapsed() < Duration::from_secs(args.duration_s) {
        sleep(Duration::from_secs(args.chaos_every_s.max(1))).await;

        if rng.gen::<f64>() < args.kill_prob {
            // kill & restart a random node
            let idx = rng.gen_range(0..args.nodes);
            if let Some(mut ch) = children[idx].take() {
                let _ = ch.kill();
                let _ = ch.wait();
            }
            let dir = node_dir(&args.data_dir, idx+1);
            children[idx] = Some(spawn_node(&dir)?);
            eprintln!("[chaos] restarted node{}", idx+1);
        } else {
            // partition shuffle: split nodes into two groups and re-write peers then restart all
            let mut group_a = vec![];
            let mut group_b = vec![];
            for i in 0..args.nodes {
                if rng.gen::<bool>() { group_a.push(i); } else { group_b.push(i); }
            }
            if group_a.is_empty() || group_b.is_empty() { continue; }

            for &i in group_a.iter().chain(group_b.iter()) {
                if let Some(mut ch) = children[i].take() {
                    let _ = ch.kill();
                    let _ = ch.wait();
                }
            }

            for &i in group_a.iter() {
                let peers = group_a.iter().filter(|&&j| j!=i).map(|&j| format!("/ip4/127.0.0.1/tcp/{}", args.p2p_port_base + j as u16)).collect();
                let dir = node_dir(&args.data_dir, i+1);
                write_config(&dir, (i+1) as u64, chain_id, args.p2p_port_base + i as u16, args.rpc_port_base + i as u16, peers)?;
                children[i] = Some(spawn_node(&dir)?);
            }
            for &i in group_b.iter() {
                let peers = group_b.iter().filter(|&&j| j!=i).map(|&j| format!("/ip4/127.0.0.1/tcp/{}", args.p2p_port_base + j as u16)).collect();
                let dir = node_dir(&args.data_dir, i+1);
                write_config(&dir, (i+1) as u64, chain_id, args.p2p_port_base + i as u16, args.rpc_port_base + i as u16, peers)?;
                children[i] = Some(spawn_node(&dir)?);
            }

            eprintln!("[chaos] applied partition shuffle: A={} B={}", group_a.len(), group_b.len());
        }
    }

    for i in 0..args.nodes {
        if let Some(mut ch) = children[i].take() {
            let _ = ch.kill();
            let _ = ch.wait();
        }
    }

    Ok(())
}
