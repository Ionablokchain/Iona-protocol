//! IONA EVM RPC Server
//!
//! Standalone JSON‑RPC server that exposes Ethereum‑compatible APIs
//! backed by IONA's EVM execution engine.
//!
//! Supports:
//! - State persistence (snapshots)
//! - Append‑only chain database (blocks, receipts, transactions, logs)
//! - Optional block production (automatic mining)
//!
//! # Example
//!
//! ```bash
//! iona-evm-rpc --listen 0.0.0.0:8545 --block-time-ms 3000
//! ```

use clap::Parser;
use iona::rpc::eth_rpc::EthRpcState;
use iona::rpc::router::build_router;
use std::net::SocketAddr;
use std::path::PathBuf;
use thiserror::Error;
use tokio::net::TcpListener;
use tokio::time::{sleep, Duration};

// -----------------------------------------------------------------------------
// Constants
// -----------------------------------------------------------------------------

/// Default listen address.
const DEFAULT_LISTEN: &str = "127.0.0.1:8545";

/// Default maximum transactions per mined block.
const DEFAULT_MAX_TXS: u64 = 256;

/// Default block time in milliseconds (0 = no automatic mining).
const DEFAULT_BLOCK_TIME_MS: u64 = 0;

/// Default automine behaviour (mine immediately on tx submission).
const DEFAULT_AUTOMINE: bool = true;

/// Minimum allowed block time (ms) – prevents excessive CPU usage.
const MIN_BLOCK_TIME_MS: u64 = 100;

// -----------------------------------------------------------------------------
// Errors
// -----------------------------------------------------------------------------

/// Errors that can occur during EVM RPC server startup.
#[derive(Debug, Error)]
pub enum EvmRpcError {
    #[error("invalid listen address: {0}")]
    InvalidListenAddress(#[from] std::net::AddrParseError),

    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("chain store error: {0}")]
    ChainStore(String),

    #[error("snapshot error: {0}")]
    Snapshot(String),

    #[error("block time too low: {0}ms (minimum {MIN_BLOCK_TIME_MS}ms)")]
    BlockTimeTooLow(u64),
}

pub type EvmRpcResult<T> = Result<T, EvmRpcError>;

// -----------------------------------------------------------------------------
// CLI Arguments
// -----------------------------------------------------------------------------

#[derive(Parser, Debug)]
#[command(name = "iona-evm-rpc")]
#[command(about = "IONA EVM JSON‑RPC server", long_about = None)]
struct Args {
    /// Data directory for state persistence (snapshots).
    #[arg(long)]
    data_dir: Option<PathBuf>,

    /// Append‑only chain DB directory (JSONL files). If set, loads blocks/receipts/txs/logs from files.
    #[arg(long)]
    chain_db_dir: Option<PathBuf>,

    /// If set, prune and compact chain DB at startup to keep last N blocks.
    #[arg(long)]
    prune_keep_blocks: Option<usize>,

    /// Listen address (e.g., 127.0.0.1:8545).
    #[arg(long, default_value = DEFAULT_LISTEN)]
    listen: String,

    /// Block time in milliseconds. If > 0, produces blocks periodically by calling `iona_mine` internally.
    #[arg(long, default_value_t = DEFAULT_BLOCK_TIME_MS)]
    block_time_ms: u64,

    /// Maximum transactions per produced block.
    #[arg(long, default_value_t = DEFAULT_MAX_TXS)]
    max_txs: u64,

    /// Disable automine (do not mine immediately on `eth_sendRawTransaction`).
    #[arg(long, default_value_t = !DEFAULT_AUTOMINE)]
    no_automine: bool,
}

// -----------------------------------------------------------------------------
// Helper functions
// -----------------------------------------------------------------------------

/// Load state from snapshot if available.
fn load_snapshot(st: &mut EthRpcState, data_dir: &PathBuf) -> EvmRpcResult<()> {
    match iona::rpc::fs_store::load_snapshot(data_dir) {
        Ok(Some(snapshot)) => {
            iona::rpc::fs_store::apply_snapshot_to_state(st, snapshot)
                .map_err(|e| EvmRpcError::Snapshot(e.to_string()))?;
            tracing::info!(?data_dir, "state snapshot loaded");
        }
        Ok(None) => {
            tracing::info!(?data_dir, "no existing snapshot, starting fresh");
        }
        Err(e) => {
            return Err(EvmRpcError::Snapshot(e.to_string()));
        }
    }
    Ok(())
}

/// Load chain database and optionally prune it.
fn load_chain_db(st: &mut EthRpcState, chain_db_dir: &PathBuf, prune_keep_blocks: Option<usize>) -> EvmRpcResult<()> {
    st.chain_db_dir = Some(chain_db_dir.clone());
    if let Err(e) = iona::rpc::chain_store::load_into_state(chain_db_dir, st) {
        tracing::warn!(error = %e, "failed to load chain DB (continuing with empty state)");
    } else {
        tracing::info!(?chain_db_dir, "chain DB loaded");
    }

    if let Some(keep) = prune_keep_blocks {
        if let Err(e) = iona::rpc::chain_store::prune_and_compact(chain_db_dir, st, keep) {
            tracing::warn!(error = %e, "failed to prune chain DB (continuing)");
        } else {
            tracing::info!(keep, "chain DB pruned and compacted");
        }
    }
    Ok(())
}

/// Spawn background block producer if block_time_ms > 0.
fn spawn_block_producer(st: EthRpcState, block_time_ms: u64, max_txs: usize) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let interval = Duration::from_millis(block_time_ms);
        loop {
            sleep(interval).await;
            let tx_count = st.txpool.lock().unwrap().len();
            if tx_count > 0 {
                if let Err(e) = iona::rpc::eth_rpc::mine_pending_block_public(&st, max_txs) {
                    tracing::warn!(error = %e, "background mining failed");
                }
            }
        }
    })
}

// -----------------------------------------------------------------------------
// Main
// -----------------------------------------------------------------------------

#[tokio::main]
async fn main() -> EvmRpcResult<()> {
    let args = Args::parse();

    // Validate block time.
    if args.block_time_ms > 0 && args.block_time_ms < MIN_BLOCK_TIME_MS {
        return Err(EvmRpcError::BlockTimeTooLow(args.block_time_ms));
    }

    // Initialize state.
    let mut state = EthRpcState::default();
    state.automine = !args.no_automine;

    // Load snapshot if data directory provided.
    if let Some(ref dir) = args.data_dir {
        load_snapshot(&mut state, dir)?;
        state.persist_dir = Some(dir.clone());
    }

    // Load chain DB if provided.
    if let Some(ref dir) = args.chain_db_dir {
        load_chain_db(&mut state, dir, args.prune_keep_blocks)?;
    }

    // Parse listen address.
    let addr: SocketAddr = args.listen.parse()?;

    // Build router.
    let app = build_router(state.clone());

    // Start background block producer if needed.
    let _producer_handle = if args.block_time_ms > 0 {
        Some(spawn_block_producer(state, args.block_time_ms, args.max_txs as usize))
    } else {
        None
    };

    // Start server.
    let listener = TcpListener::bind(addr).await?;
    tracing::info!(%addr, "EVM RPC server listening");
    axum::serve(listener, app).await?;

    Ok(())
}
