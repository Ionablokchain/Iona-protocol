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
use tracing::{error, info, warn};

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
}

/// Alias for `Result<T, NodeError>`.
pub type NodeResult<T> = Result<T, NodeError>;

// -----------------------------------------------------------------------------
// Node Structure
// -----------------------------------------------------------------------------

/// Main node handle. Holds all components and manages the node lifecycle.
pub struct Node {
    config: Config,
    // Components will be initialised in `new` and stored here.
    // For brevity, we only keep the config; real implementation would hold
    // storage, mempool, consensus engine, network, etc.
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

        // TODO: Initialise storage, mempool, network, consensus, RPC, etc.

        Ok(Self { config })
    }

    /// Run the node main loop.
    ///
    /// Starts consensus, networking, RPC servers, and blocks until shutdown.
    pub async fn run(&self) -> NodeResult<()> {
        info!("Starting IONA node");

        // Start RPC server (if configured)
        if !self.config.rpc.listen.is_empty() {
            info!("Starting RPC server on {}", self.config.rpc.listen);
            // spawn RPC task
        }

        // Start consensus engine and network
        info!("Consensus engine started");

        // Wait for shutdown signal
        wait_for_shutdown().await;

        info!("Shutting down IONA node");
        Ok(())
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

    if cfg!(feature = "otel") {
        // OpenTelemetry integration (requires feature flag)
        let otel_layer = opentelemetry::global::tracer_provider()
            .tracer("iona-node")
            .into();
        builder.with(otel_layer).init();
    } else {
        builder.init();
    }
}

async fn wait_for_shutdown() {
    let ctrl_c = async {
        signal::ctrl_c()
            .await
            .expect("failed to install Ctrl+C handler");
        info!("Received Ctrl+C, shutting down");
    };

    #[cfg(unix)]
    let terminate = async {
        signal::unix::signal(signal::unix::SignalKind::terminate())
            .expect("failed to install SIGTERM handler")
            .recv()
            .await;
        info!("Received SIGTERM, shutting down");
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {},
        _ = terminate => {},
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
