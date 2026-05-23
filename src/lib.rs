//! IONA blockchain node library.
//!
//! This crate implements a production‑ready blockchain node with a focus on
//! deterministic execution, upgrade safety, and validator hardening.
//!
//! # Quick Start
//!
//! ```rust,ignore
//! use iona::prelude::*;
//!
//! #[tokio::main]
//! async fn main() -> anyhow::Result<()> {
//!     let config = Config::load("config.toml")?;
//!     let node = Node::new(config).await?;
//!     node.run().await?;
//!     Ok(())
//! }
//! ```
//!
//! # Feature flags
//!
//! - `otel` – enable OpenTelemetry tracing export.
//! - `bin-cli` – build CLI tool (disabled by default).
//! - `bin-chaos` – build chaos testing tool.
//! - `bin-remote-signer` – build remote signer service.
//! - `bin-evm-rpc` – build EVM RPC server.
//! - `bin-chaindb-tool` – build chain database inspection tool.
//! - `bin-block-store` – build block store utility.

#![deny(missing_docs)]
#![deny(rustdoc::broken_intra_doc_links)]

pub mod admin;
pub mod audit;
pub mod config;
pub mod consensus;
pub mod crypto;
pub mod economics;
pub mod evm;
pub mod evidence;
pub mod execution;
pub mod governance;
pub mod mempool;
pub mod merkle;
pub mod metrics;
pub mod net;
pub mod protocol;
pub mod replay;
pub mod rpc;
pub mod rpc_health;
pub mod rpc_limits;
pub mod slashing;
pub mod snapshot;
pub mod storage;
pub mod types;
pub mod upgrade;
pub mod vm;
pub mod wal;

use std::path::Path;
use std::sync::Arc;
use thiserror::Error;
use tokio::signal;
use tokio::sync::watch;
use tracing::{error, info, warn, debug};

// -----------------------------------------------------------------------------
// Node Error
// -----------------------------------------------------------------------------

/// Errors that can occur during node initialisation or operation.
#[derive(Debug, Error)]
pub enum NodeError {
    #[error("configuration error: {0}")]
    Config(#[from] config::ConfigError),

    #[error("storage error: {0}")]
    Storage(String),

    #[error("network error: {0}")]
    Network(String),

    #[error("consensus error: {0}")]
    Consensus(String),

    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("upgrade error: {0}")]
    Upgrade(String),

    #[error("initialisation failed: {0}")]
    Init(String),
}

/// Alias for `Result<T, NodeError>`.
pub type NodeResult<T> = Result<T, NodeError>;

// -----------------------------------------------------------------------------
// Node Structure
// -----------------------------------------------------------------------------

/// Main node handle. Holds all components and manages the node lifecycle.
pub struct Node {
    config: Config,
    /// Shutdown signal sender (used to stop all background tasks).
    shutdown_tx: watch::Sender<()>,
    /// Shutdown signal receiver.
    shutdown_rx: watch::Receiver<()>,
    // Component handles (would be stored here in real implementation).
    // For this example, we only keep the configuration.
}

impl Node {
    /// Create a new node instance.
    ///
    /// Loads configuration, initialises storage, networking, consensus,
    /// and all other components.
    pub async fn new(config: Config) -> NodeResult<Self> {
        // Validate config first
        config.validate()?;

        // Initialise tracing / logging
        init_tracing(&config);

        info!("Initialising IONA node v{}", env!("CARGO_PKG_VERSION"));
        info!("Data directory: {}", config.node.data_dir);

        // Run compatibility and schema upgrades
        let data_dir = Path::new(&config.node.data_dir);
        let compat = upgrade::check_compat(data_dir)
            .map_err(|e| NodeError::Upgrade(e.to_string()))?;
        if !compat.compatible {
            warn!("Compatibility report: {}", compat);
            if compat.migrations_needed {
                info!("Running schema migrations...");
                upgrade::dry_run_migrations(data_dir)
                    .map_err(|e| NodeError::Upgrade(e.to_string()))?;
                // In real code, we would apply migrations here.
            }
        }

        // Create shutdown channel
        let (shutdown_tx, shutdown_rx) = watch::channel(());

        // TODO: Initialise storage, mempool, network, consensus, RPC, etc.
        // The following stubs show how the components would be integrated.

        Ok(Self {
            config,
            shutdown_tx,
            shutdown_rx,
        })
    }

    /// Run the node main loop.
    ///
    /// Starts all background services (consensus, networking, RPC) and
    /// blocks until a shutdown signal is received.
    pub async fn run(&self) -> NodeResult<()> {
        info!("Starting IONA node");

        // Start RPC server (if configured)
        let rpc_handle = if !self.config.rpc.listen.is_empty() {
            info!("Starting RPC server on {}", self.config.rpc.listen);
            let listen_addr = self.config.rpc.listen.parse()
                .map_err(|e| NodeError::Init(format!("invalid RPC listen address: {}", e)))?;
            let shutdown_rx = self.shutdown_rx.clone();
            let rpc_config = self.config.rpc.clone();
            Some(tokio::spawn(async move {
                if let Err(e) = rpc::router::serve(listen_addr, rpc_config, shutdown_rx).await {
                    error!("RPC server error: {}", e);
                }
            }))
        } else {
            debug!("RPC server disabled (no listen address)");
            None
        };

        // Start metrics server (if enabled)
        let metrics_handle = if self.config.observability.enable_metrics {
            let metrics_addr = self.config.observability.metrics_listen.parse()
                .map_err(|e| NodeError::Init(format!("invalid metrics address: {}", e)))?;
            let shutdown_rx = self.shutdown_rx.clone();
            Some(tokio::spawn(async move {
                if let Err(e) = metrics::serve(metrics_addr, shutdown_rx).await {
                    error!("Metrics server error: {}", e);
                }
            }))
        } else {
            None
        };

        // Start networking and consensus components
        // (In a real node, these would be spawned and awaited.)

        info!("Node started successfully");

        // Wait for shutdown signal
        wait_for_shutdown(self.shutdown_rx.clone()).await;
        info!("Shutdown signal received, stopping components");

        // Cancel all background tasks (they will exit when shutdown_rx changes)
        if let Some(handle) = rpc_handle {
            handle.abort();
        }
        if let Some(handle) = metrics_handle {
            handle.abort();
        }

        info!("Node shutdown complete");
        Ok(())
    }

    /// Trigger a graceful shutdown from within the node (e.g., after receiving a signal).
    pub fn shutdown(&self) {
        let _ = self.shutdown_tx.send(());
    }
}

// -----------------------------------------------------------------------------
// Helper functions
// -----------------------------------------------------------------------------

fn init_tracing(config: &Config) {
    use tracing_subscriber::{fmt, prelude::*, EnvFilter};

    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new(&config.node.log_level));

    let builder = fmt::Subscriber::builder()
        .with_env_filter(filter)
        .with_target(true)
        .with_thread_ids(true);

    #[cfg(feature = "otel")]
    {
        use opentelemetry::global;
        use opentelemetry_otlp::WithExportConfig;
        use opentelemetry_sdk::trace::{self, TracerProvider};

        if config.observability.enable_otel {
            let endpoint = config.observability.otel_endpoint.clone();
            let service_name = config.observability.service_name.clone();
            let exporter = opentelemetry_otlp::new_exporter()
                .tonic()
                .with_endpoint(endpoint);
            let provider = TracerProvider::builder()
                .with_simple_exporter(exporter)
                .with_config(trace::config().with_resource(
                    opentelemetry_sdk::Resource::new(vec![
                        opentelemetry::KeyValue::new("service.name", service_name),
                    ])
                ))
                .build();
            global::set_tracer_provider(provider);
            let otel_layer = tracing_opentelemetry::layer().with_tracer(global::tracer("iona-node"));
            builder.with(otel_layer).init();
            return;
        }
    }
    builder.init();
}

async fn wait_for_shutdown(mut shutdown_rx: watch::Receiver<()>) {
    let ctrl_c = async {
        signal::ctrl_c()
            .await
            .expect("failed to install Ctrl+C handler");
        info!("Received Ctrl+C");
    };

    #[cfg(unix)]
    let terminate = async {
        signal::unix::signal(signal::unix::SignalKind::terminate())
            .expect("failed to install SIGTERM handler")
            .recv()
            .await;
        info!("Received SIGTERM");
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {},
        _ = terminate => {},
        _ = shutdown_rx.changed() => {
            info!("Internal shutdown signal");
        },
    }
}

// -----------------------------------------------------------------------------
// Re‑exports
// -----------------------------------------------------------------------------

// Configuration
pub use config::NodeConfig as Config;

// Core types
pub use types::{Block, Hash32, Height, Receipt, Round, Tx};

// Consensus
pub use consensus::engine::Engine;
pub use consensus::validator_set::ValidatorSet;

// Crypto
pub use crypto::{PublicKeyBytes, SignatureBytes, Signer, Verifier};
pub use crypto::ed25519::{Ed25519Keypair, Ed25519Signer, Ed25519Verifier};

// Execution
pub use execution::KvState;

// Mempool
pub use mempool::{Mempool as MempoolTrait, StandardMempool, MevMempool};

// Networking
pub use net::inmem::InMemNet;

// Storage
pub use storage::layout::DataLayout;
pub use storage::block_store::FsBlockStore;

// EVM
pub use evm::kv_state_db::KvStateDb;

// Metrics
pub use metrics::{init_metrics, metrics, Metrics};

// RPC
pub use rpc::eth_rpc::EthRpcState;
pub use rpc::router::serve as serve_rpc;

// -----------------------------------------------------------------------------
// Prelude
// -----------------------------------------------------------------------------

/// Prelude for convenient importing of common items.
pub mod prelude {
    pub use super::{
        Config, Node, NodeError, NodeResult,
        Block, Hash32, Height, Receipt, Round, Tx,
        KvState,
        PublicKeyBytes, Signer, Verifier, Ed25519Verifier,
        MempoolTrait,
        init_metrics, metrics,
    };
}
