//! IONA EVM JSON‑RPC server.
//!
//! Provides an Ethereum‑compatible JSON‑RPC endpoint with optional block production
//! (automine or periodic mining) and persistence to disk.

use clap::Parser;
use iona::rpc::router::build_router;
use iona::rpc::eth_rpc::EthRpcState;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::TcpListener;
use tokio::signal;
use tokio::time::{sleep, Duration};
use tracing::{error, info, warn};

// -----------------------------------------------------------------------------
// Command-line arguments
// -----------------------------------------------------------------------------

/// IONA EVM RPC server
#[derive(Parser, Debug)]
#[command(name = "iona-evm-rpc", about = "Ethereum‑compatible JSON‑RPC server for IONA")]
struct Args {
    /// Data directory for state snapshot persistence.
    #[arg(long)]
    data_dir: Option<String>,

    /// Append‑only chain database directory (JSONL). If set, loads blocks/receipts/txs/logs from files
    /// and appends new ones.
    #[arg(long)]
    chain_db_dir: Option<String>,

    /// If set, prune and compact the chain DB at startup to keep only the last N blocks.
    #[arg(long)]
    prune_keep_blocks: Option<usize>,

    /// Listen address (e.g., 127.0.0.1:8545).
    #[arg(long, default_value = "127.0.0.1:8545")]
    listen: String,

    /// Block time in milliseconds. If > 0, produces blocks periodically by calling `iona_mine` internally.
    #[arg(long, default_value_t = 0)]
    block_time_ms: u64,

    /// Maximum number of transactions per produced block.
    #[arg(long, default_value_t = 256)]
    max_txs: u64,

    /// Disable automine (do not mine immediately on `sendRawTransaction`).
    #[arg(long, default_value_t = false)]
    no_automine: bool,

    /// Log level (trace, debug, info, warn, error). Default is info.
    #[arg(long, default_value = "info")]
    log_level: String,
}

// -----------------------------------------------------------------------------
// Main entry point
// -----------------------------------------------------------------------------

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = Args::parse();

    // Initialize logging with structured output.
    init_logging(&args.log_level)?;

    info!("Starting IONA EVM RPC server (version {})", env!("CARGO_PKG_VERSION"));

    // Create RPC state.
    let mut st = EthRpcState::default();

    // Load snapshot if data_dir provided.
    if let Some(dir) = &args.data_dir {
        st.persist_dir = Some(dir.clone());
        match iona::rpc::fs_store::load_snapshot(dir) {
            Ok(Some(snap)) => {
                info!(directory = dir, "loaded state snapshot");
                iona::rpc::fs_store::apply_snapshot_to_state(&mut st, snap);
            }
            Ok(None) => info!(directory = dir, "no snapshot found, starting fresh"),
            Err(e) => {
                warn!(directory = dir, error = %e, "failed to load snapshot");
            }
        }
    }

    // Load chain DB if provided.
    if let Some(cdir) = &args.chain_db_dir {
        st.chain_db_dir = Some(cdir.clone());
        match iona::rpc::chain_store::load_into_state(cdir, &mut st) {
            Ok(_) => info!(directory = cdir, "loaded chain database"),
            Err(e) => warn!(directory = cdir, error = %e, "failed to load chain database"),
        }

        // Prune if requested.
        if let Some(keep) = args.prune_keep_blocks {
            if let Err(e) = iona::rpc::chain_store::prune_and_compact(cdir, &st, keep) {
                warn!(directory = cdir, keep, error = %e, "pruning failed");
            } else {
                info!(directory = cdir, keep, "pruned chain database");
            }
        }
    }

    // Apply automine settings.
    st.automine = !args.no_automine;

    // Build the HTTP router with the state.
    let app = build_router(st.clone());

    // Start periodic block production if requested.
    if args.block_time_ms > 0 {
        let st2 = st.clone();
        let block_time = Duration::from_millis(args.block_time_ms);
        let max_txs = args.max_txs as usize;
        tokio::spawn(async move {
            info!(block_time_ms = args.block_time_ms, max_txs, "starting periodic block production");
            loop {
                sleep(block_time).await;
                let txpool_len = st2.txpool.lock().unwrap().len();
                if txpool_len > 0 {
                    if let Err(e) = iona::rpc::eth_rpc::mine_pending_block_public(&st2, max_txs) {
                        error!(error = %e, "periodic mining failed");
                    } else {
                        debug!("periodic block mined");
                    }
                }
            }
        });
    }

    // Start the HTTP server.
    let addr: SocketAddr = args.listen.parse()?;
    let listener = TcpListener::bind(addr).await?;
    info!("listening on http://{}", addr);

    // Run server with graceful shutdown.
    let server = axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal());

    if let Err(e) = server.await {
        error!("server error: {}", e);
        return Err(e.into());
    }

    info!("server shut down gracefully");
    Ok(())
}

// -----------------------------------------------------------------------------
// Logging initialization
// -----------------------------------------------------------------------------

/// Initialize the global logger with the given level.
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

// -----------------------------------------------------------------------------
// Graceful shutdown signal
// -----------------------------------------------------------------------------

/// Wait for a shutdown signal (Ctrl+C or SIGTERM).
async fn shutdown_signal() {
    let ctrl_c = async {
        signal::ctrl_c()
            .await
            .expect("failed to install Ctrl+C handler");
    };

    #[cfg(unix)]
    let terminate = async {
        use signal::unix::{signal, SignalKind};
        let mut signal = signal(SignalKind::terminate())
            .expect("failed to install SIGTERM handler");
        signal.recv().await;
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {},
        _ = terminate => {},
    }
    info!("shutdown signal received");
}
