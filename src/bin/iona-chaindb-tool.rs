//! IONA chain database tool – inspect, prune, and compact JSONL chain storage.
//!
//! This tool provides operations on the append‑only chain database used by the RPC layer.
//!
//! # Commands
//!
//! - `info` – print meta information and counts of blocks, receipts, transactions, logs.
//! - `prune-compact` – keep only the last N blocks, compact the JSONL files and rebuild indices.
//! - `compact` – rebuild in‑memory state from files and write fresh compacted files.
//!
//! # Usage
//!
//! ```bash
//! cargo run --bin iona-chaindb-tool -- --chain-db-dir ./chaindb info
//! cargo run --bin iona-chaindb-tool -- --chain-db-dir ./chaindb prune-compact --keep-blocks 10000
//! ```

use clap::{Parser, Subcommand};
use iona::rpc::eth_rpc::EthRpcState;
use tracing::{info, warn};

// -----------------------------------------------------------------------------
// Command-line arguments
// -----------------------------------------------------------------------------

#[derive(Parser, Debug)]
#[command(name = "iona-chaindb-tool", about = "Inspect and manipulate the IONA chain database")]
struct Args {
    /// Chain database directory (JSONL files).
    #[arg(long, default_value = "./chaindb")]
    chain_db_dir: String,

    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand, Debug)]
enum Cmd {
    /// Print meta information and record counts.
    Info,
    /// Prune to keep last N blocks, compact files, and rebuild indices.
    PruneCompact {
        /// Number of most recent blocks to keep.
        #[arg(long, default_value_t = 10_000)]
        keep_blocks: usize,
    },
    /// Rebuild in‑memory state from files and then write fresh compacted files.
    Compact {
        /// Number of most recent blocks to keep.
        #[arg(long, default_value_t = 10_000)]
        keep_blocks: usize,
    },
}

// -----------------------------------------------------------------------------
// Main
// -----------------------------------------------------------------------------

fn main() -> anyhow::Result<()> {
    let args = Args::parse();

    // Initialise logging (stderr, plain text for CLI tool).
    init_logging();

    info!("Starting IONA chain database tool (version {})", env!("CARGO_PKG_VERSION"));

    match args.cmd {
        Cmd::Info => {
            cmd_info(&args.chain_db_dir)?;
        }
        Cmd::PruneCompact { keep_blocks } => {
            cmd_prune_compact(&args.chain_db_dir, keep_blocks)?;
        }
        Cmd::Compact { keep_blocks } => {
            cmd_compact(&args.chain_db_dir, keep_blocks)?;
        }
    }

    Ok(())
}

// -----------------------------------------------------------------------------
// Command implementations
// -----------------------------------------------------------------------------

/// Print meta information and record counts.
fn cmd_info(chain_db_dir: &str) -> anyhow::Result<()> {
    info!("Loading meta from {}", chain_db_dir);
    let meta = iona::rpc::chain_store::ensure_meta(chain_db_dir)?;
    println!(
        "meta: schema_version={}, created_at_unix={}",
        meta.schema_version, meta.created_at_unix
    );

    let files = iona::rpc::chain_store::files(chain_db_dir);
    let blocks: Vec<iona::rpc::eth_rpc::Block> =
        iona::rpc::chain_store::load_jsonl(&files.blocks).unwrap_or_default();
    let receipts: Vec<iona::rpc::eth_rpc::Receipt> =
        iona::rpc::chain_store::load_jsonl(&files.receipts).unwrap_or_default();
    let txs: Vec<iona::rpc::eth_rpc::TxRecord> =
        iona::rpc::chain_store::load_jsonl(&files.txs).unwrap_or_default();
    let logs: Vec<iona::rpc::eth_rpc::Log> =
        iona::rpc::chain_store::load_jsonl(&files.logs).unwrap_or_default();

    println!(
        "blocks={} receipts={} txs={} logs={}",
        blocks.len(),
        receipts.len(),
        txs.len(),
        logs.len()
    );
    info!("Info command completed");
    Ok(())
}

/// Prune and compact the chain database.
fn cmd_prune_compact(chain_db_dir: &str, keep_blocks: usize) -> anyhow::Result<()> {
    info!(keep_blocks, "Prune and compact operation started");
    let mut st = EthRpcState::default();
    st.chain_db_dir = Some(chain_db_dir.to_string());

    info!("Loading state from chain database");
    iona::rpc::chain_store::load_into_state(chain_db_dir, &mut st)?;

    info!("Pruning and compacting (keeping last {} blocks)", keep_blocks);
    iona::rpc::chain_store::prune_and_compact(chain_db_dir, &st, keep_blocks)?;

    println!("done");
    info!("Prune and compact completed");
    Ok(())
}

/// Rebuild the chain database from scratch (compact) without pruning first.
fn cmd_compact(chain_db_dir: &str, keep_blocks: usize) -> anyhow::Result<()> {
    info!(keep_blocks, "Compact operation started");
    let mut st = EthRpcState::default();
    st.chain_db_dir = Some(chain_db_dir.to_string());

    info!("Loading state from chain database");
    iona::rpc::chain_store::load_into_state(chain_db_dir, &mut st)?;

    info!("Compacting (keeping last {} blocks)", keep_blocks);
    iona::rpc::chain_store::prune_and_compact(chain_db_dir, &st, keep_blocks)?;

    println!("done");
    info!("Compact completed");
    Ok(())
}

// -----------------------------------------------------------------------------
// Logging initialisation (simple text output for CLI)
// -----------------------------------------------------------------------------

fn init_logging() {
    use tracing_subscriber::{fmt, prelude::*, EnvFilter};

    // For CLI tool, we use plain text with INFO level by default.
    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new("info"));

    let subscriber = fmt::Subscriber::builder()
        .with_target(false)
        .with_thread_ids(false)
        .with_env_filter(filter)
        .finish();

    let _ = tracing::subscriber::set_global_default(subscriber);
}
