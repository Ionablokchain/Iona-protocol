//! IONA EVM RPC Server — Production‑ready Ethereum‑compatible JSON‑RPC server.
//!
//! Backed by IONA's EVM execution engine with state persistence and append‑only chain database.
//!
//! # Features
//! - Automatic snapshotting (configurable interval)
//! - Chain DB flush (configurable interval or block count)
//! - Graceful shutdown
//! - Health and metrics endpoints
//! - Automatic block production (mining) with configurable interval
//! - Structured logging (JSON or pretty)
//!
//! # Example
//! ```bash
//! iona-evm-rpc \
//!   --data-dir ./state \
//!   --chain-db-dir ./chaindb \
//!   --listen 0.0.0.0:8545 \
//!   --block-time-ms 3000 \
//!   --snapshot-every-secs 60 \
//!   --flush-every-blocks 100
//! ```

use axum::response::Json;
use axum::routing::get;
use axum::Router;
use clap::Parser;
use iona::rpc::eth_rpc::EthRpcState;
use iona::rpc::router::build_router;
use prometheus::{register_counter, Counter, Encoder, TextEncoder};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use thiserror::Error;
use tokio::net::TcpListener;
use tokio::signal;
use tokio::sync::Mutex;
use tokio::time::interval;
use tracing::{error, info, warn};
use tracing_subscriber::{EnvFilter, FmtSubscriber};

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

/// Default snapshot interval in seconds (0 = disabled).
const DEFAULT_SNAPSHOT_EVERY_SECS: u64 = 60;

/// Default flush interval in seconds (0 = disabled).
const DEFAULT_FLUSH_EVERY_SECS: u64 = 10;

/// Default flush every N blocks (0 = disabled).
const DEFAULT_FLUSH_EVERY_BLOCKS: u64 = 100;

/// Default log level.
const DEFAULT_LOG_LEVEL: &str = "info";

// -----------------------------------------------------------------------------
// Errors
// -----------------------------------------------------------------------------

/// Errors that can occur during EVM RPC server startup or runtime.
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

    #[error("invalid log format: {0} (expected 'json' or 'pretty')")]
    InvalidLogFormat(String),
}

pub type EvmRpcResult<T> = Result<T, EvmRpcError>;

// -----------------------------------------------------------------------------
// Prometheus metrics
// -----------------------------------------------------------------------------

lazy_static::lazy_static! {
    static ref RPC_REQUESTS: Counter = register_counter!("rpc_requests_total", "Total RPC requests").unwrap();
    static ref BLOCKS_MINED: Counter = register_counter!("blocks_mined_total", "Total blocks mined").unwrap();
    static ref TXS_SUBMITTED: Counter = register_counter!("transactions_submitted_total", "Total transactions submitted").unwrap();
}

// -----------------------------------------------------------------------------
// CLI Arguments
// -----------------------------------------------------------------------------

#[derive(Parser, Debug)]
#[command(name = "iona-evm-rpc")]
#[command(about = "IONA EVM JSON‑RPC server (production‑ready)", long_about = None)]
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

    /// Snapshot interval in seconds (0 = disabled). Saves state to data_dir periodically.
    #[arg(long, default_value_t = DEFAULT_SNAPSHOT_EVERY_SECS)]
    snapshot_every_secs: u64,

    /// Flush chain DB to disk every N blocks (0 = disabled).
    #[arg(long, default_value_t = DEFAULT_FLUSH_EVERY_BLOCKS)]
    flush_every_blocks: u64,

    /// Flush chain DB to disk every N seconds (0 = disabled).
    #[arg(long, default_value_t = DEFAULT_FLUSH_EVERY_SECS)]
    flush_every_secs: u64,

    /// Override chain ID (default from genesis).
    #[arg(long)]
    chain_id: Option<u64>,

    /// Log level (trace, debug, info, warn, error).
    #[arg(long, default_value = DEFAULT_LOG_LEVEL)]
    log_level: String,

    /// Log format: "pretty" (human‑readable) or "json" (structured).
    #[arg(long, default_value = "pretty")]
    log_format: String,
}

// -----------------------------------------------------------------------------
// Helper functions
// -----------------------------------------------------------------------------

/// Initialize tracing subscriber.
fn init_tracing(level: &str, format: &str) -> EvmRpcResult<()> {
    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new(level));
    match format {
        "json" => {
            let subscriber = FmtSubscriber::builder()
                .json()
                .with_env_filter(filter)
                .finish();
            tracing::subscriber::set_global_default(subscriber)
                .map_err(|e| EvmRpcError::Io(std::io::Error::new(std::io::ErrorKind::Other, e)))?;
        }
        "pretty" => {
            let subscriber = FmtSubscriber::builder()
                .pretty()
                .with_env_filter(filter)
                .finish();
            tracing::subscriber::set_global_default(subscriber)
                .map_err(|e| EvmRpcError::Io(std::io::Error::new(std::io::ErrorKind::Other, e)))?;
        }
        _ => return Err(EvmRpcError::InvalidLogFormat(format.to_string())),
    }
    Ok(())
}

/// Load state from snapshot if available.
async fn load_snapshot(st: &mut EthRpcState, data_dir: &PathBuf) -> EvmRpcResult<()> {
    match iona::rpc::fs_store::load_snapshot(data_dir) {
        Ok(Some(snapshot)) => {
            iona::rpc::fs_store::apply_snapshot_to_state(st, snapshot)
                .map_err(|e| EvmRpcError::Snapshot(e.to_string()))?;
            info!(?data_dir, "state snapshot loaded");
        }
        Ok(None) => {
            info!(?data_dir, "no existing snapshot, starting fresh");
        }
        Err(e) => {
            return Err(EvmRpcError::Snapshot(e.to_string()));
        }
    }
    Ok(())
}

/// Load chain database and optionally prune it.
async fn load_chain_db(st: &mut EthRpcState, chain_db_dir: &PathBuf, prune_keep_blocks: Option<usize>) -> EvmRpcResult<()> {
    st.chain_db_dir = Some(chain_db_dir.clone());
    match iona::rpc::chain_store::load_into_state(chain_db_dir, st) {
        Ok(_) => info!(?chain_db_dir, "chain DB loaded"),
        Err(e) => warn!(error = %e, "failed to load chain DB (continuing with empty state)"),
    }

    if let Some(keep) = prune_keep_blocks {
        if let Err(e) = iona::rpc::chain_store::prune_and_compact(chain_db_dir, st, keep) {
            warn!(error = %e, "failed to prune chain DB (continuing)");
        } else {
            info!(keep, "chain DB pruned and compacted");
        }
    }
    Ok(())
}

/// Spawn background snapshotter.
fn spawn_snapshotter(st: EthRpcState, data_dir: PathBuf, interval_secs: u64) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut ticker = interval(Duration::from_secs(interval_secs));
        loop {
            ticker.tick().await;
            match iona::rpc::fs_store::save_snapshot(&data_dir, &st) {
                Ok(_) => info!("snapshot saved to {:?}", data_dir),
                Err(e) => error!(error = %e, "failed to save snapshot"),
            }
        }
    })
}

/// Spawn background chain DB flusher (by block count).
fn spawn_block_flusher(st: EthRpcState, flush_every_blocks: u64) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut last_block = 0u64;
        loop {
            tokio::time::sleep(Duration::from_secs(1)).await;
            let current_height = st.chain_db_height.load(std::sync::atomic::Ordering::Relaxed);
            if current_height > last_block && (current_height - last_block) >= flush_every_blocks {
                if let Err(e) = iona::rpc::chain_store::flush_to_disk(&st) {
                    error!(error = %e, "failed to flush chain DB");
                } else {
                    info!(blocks = current_height - last_block, "chain DB flushed");
                    last_block = current_height;
                }
            }
        }
    })
}

/// Spawn background chain DB flusher (by time).
fn spawn_time_flusher(st: EthRpcState, interval_secs: u64) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut ticker = interval(Duration::from_secs(interval_secs));
        loop {
            ticker.tick().await;
            if let Err(e) = iona::rpc::chain_store::flush_to_disk(&st) {
                error!(error = %e, "failed to flush chain DB");
            } else {
                info!("chain DB flushed (time‑based)");
            }
        }
    })
}

/// Spawn background block producer if block_time_ms > 0.
fn spawn_block_producer(st: EthRpcState, block_time_ms: u64, max_txs: usize) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let interval = Duration::from_millis(block_time_ms);
        loop {
            tokio::time::sleep(interval).await;
            let tx_count = st.txpool.lock().unwrap().len();
            if tx_count > 0 {
                match iona::rpc::eth_rpc::mine_pending_block_public(&st, max_txs) {
                    Ok(block) => {
                        BLOCKS_MINED.inc();
                        info!(hash = ?block.hash, txs = block.transactions.len(), "block mined");
                    }
                    Err(e) => warn!(error = %e, "background mining failed"),
                }
            }
        }
    })
}

// -----------------------------------------------------------------------------
// Health and metrics endpoints
// -----------------------------------------------------------------------------

async fn health_handler() -> Json<serde_json::Value> {
    Json(serde_json::json!({ "status": "ok" }))
}

async fn metrics_handler() -> String {
    let encoder = TextEncoder::new();
    let metric_families = prometheus::gather();
    let mut buffer = Vec::new();
    encoder.encode(&metric_families, &mut buffer).unwrap();
    String::from_utf8(buffer).unwrap()
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

    // Initialize logging.
    init_tracing(&args.log_level, &args.log_format)?;
    info!("Starting IONA EVM RPC server");

    // Initialize state.
    let mut state = EthRpcState::default();
    state.automine = !args.no_automine;

    // Override chain ID if provided.
    if let Some(id) = args.chain_id {
        state.chain_id = id;
        info!(chain_id = id, "chain ID overridden");
    }

    // Load snapshot if data directory provided.
    if let Some(ref dir) = args.data_dir {
        load_snapshot(&mut state, dir).await?;
        state.persist_dir = Some(dir.clone());
    }

    // Load chain DB if provided.
    if let Some(ref dir) = args.chain_db_dir {
        load_chain_db(&mut state, dir, args.prune_keep_blocks).await?;
    }

    // Wrap state in Arc for sharing across tasks.
    let state = Arc::new(Mutex::new(state));

    // Spawn background tasks.
    let mut task_handles = Vec::new();

    if args.snapshot_every_secs > 0 {
        if let Some(ref dir) = args.data_dir {
            let st = state.lock().await.clone();
            let handle = spawn_snapshotter(st, dir.clone(), args.snapshot_every_secs);
            task_handles.push(handle);
            info!(interval_secs = args.snapshot_every_secs, "snapshotter started");
        } else {
            warn!("snapshot interval set but no data_dir provided; snapshotting disabled");
        }
    }

    if args.flush_every_blocks > 0 {
        let st = state.lock().await.clone();
        let handle = spawn_block_flusher(st, args.flush_every_blocks);
        task_handles.push(handle);
        info!(every_blocks = args.flush_every_blocks, "chain DB block flusher started");
    }

    if args.flush_every_secs > 0 {
        let st = state.lock().await.clone();
        let handle = spawn_time_flusher(st, args.flush_every_secs);
        task_handles.push(handle);
        info!(interval_secs = args.flush_every_secs, "chain DB time flusher started");
    }

    if args.block_time_ms > 0 {
        let st = state.lock().await.clone();
        let handle = spawn_block_producer(st, args.block_time_ms, args.max_txs as usize);
        task_handles.push(handle);
        info!(block_time_ms = args.block_time_ms, max_txs = args.max_txs, "background block producer started");
    }

    // Build RPC router (Ethereum JSON‑RPC endpoints).
    let rpc_app = build_router(state.clone());

    // Add health and metrics endpoints.
    let app = Router::new()
        .merge(rpc_app)
        .route("/health", get(health_handler))
        .route("/metrics", get(metrics_handler));

    // Parse listen address.
    let addr: SocketAddr = args.listen.parse()?;
    let listener = TcpListener::bind(addr).await?;
    info!(%addr, "EVM RPC server listening");

    // Graceful shutdown.
    let shutdown_signal = async {
        signal::ctrl_c().await.ok();
        info!("Received shutdown signal, starting graceful shutdown...");
        // Give background tasks a moment to finish.
        tokio::time::sleep(Duration::from_secs(5)).await;
    };

    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal)
        .await?;

    // Wait for background tasks to complete (they run forever, but we drop handles).
    drop(task_handles);
    info!("Server stopped.");
    Ok(())
}
