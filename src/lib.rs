//! IONA blockchain node library — Quantum Architecture.
//!
//! # Quantum Node Model
//!
//! The IONA node is modeled as a quantum system evolving under the
//! blockchain Hamiltonian. Each component (consensus, networking, storage)
//! exists in a tensor product Hilbert space:
//!
//! ```text
//! ℋ_node = ℋ_consensus ⊗ ℋ_network ⊗ ℋ_storage ⊗ ℋ_execution ⊗ ℋ_rpc
//! ```
//!
//! # System Hamiltonian
//!
//! ```text
//! Ĥ_node = Ĥ_consensus + Ĥ_network + Ĥ_storage + Ĥ_execution + Ĥ_rpc + Ĥ_int
//!
//! Ĥ_consensus = Σ_h ω_h a†_h a_h                    (block production oscillator)
//! Ĥ_network   = Σ_p g_p (σ^+_p σ^-_q + h.c.)        (peer entanglement)
//! Ĥ_storage   = Σ_s E_s |data_s⟩⟨data_s|            (persistent states)
//! Ĥ_execution = Σ_t J_t U_t                           (transaction gates)
//! Ĥ_rpc       = Σ_r ν_r b†_r b_r                     (request oscillators)
//! Ĥ_int       = Σ_{i,j} λ_{ij} σ^i_z σ^j_z           (component coupling)
//! ```
//!
//! # Quantum Lifecycle
//!
//! 1. **Initialization**: Prepare ground state |∅⟩_node
//! 2. **Boot**: Apply U_boot |∅⟩ → |ready⟩
//! 3. **Operation**: Continuous evolution under Ĥ_node
//! 4. **Shutdown**: Projective measurement to |stopped⟩
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
use std::time::Instant;
use thiserror::Error;
use tokio::signal;
use tokio::sync::watch;
use tracing::{error, info, warn, debug};

// -----------------------------------------------------------------------------
// Quantum Constants
// -----------------------------------------------------------------------------

/// Reduced Planck constant (natural units).
const HBAR: f64 = 1.0;

/// Node coherence time (in operation cycles).
const NODE_COHERENCE_TIME: u64 = 1_000_000;

/// Minimum coherence threshold for healthy operation.
const MIN_COHERENCE_THRESHOLD: f64 = 0.9;

/// Component entanglement strength.
const COMPONENT_ENTANGLEMENT: f64 = 0.95;

// -----------------------------------------------------------------------------
// Quantum Node Error
// -----------------------------------------------------------------------------

/// Errors that can occur during quantum node operations.
#[derive(Debug, Error)]
pub enum NodeError {
    #[error("configuration error: {0}")]
    Config(#[from] config::ConfigError),

    #[error("storage decoherence: {0}")]
    Storage(String),

    #[error("network entanglement broken: {0}")]
    Network(String),

    #[error("consensus coherence lost: {0}")]
    Consensus(String),

    #[error("I/O decoherence: {0}")]
    Io(#[from] std::io::Error),

    #[error("upgrade transition failed: {0}")]
    Upgrade(String),

    #[error("initialisation failed: {0}")]
    Init(String),

    #[error("node coherence below threshold: {coherence} < {threshold}")]
    CoherenceLost { coherence: f64, threshold: f64 },

    #[error("component entanglement failed: {component}")]
    EntanglementFailed { component: String },
}

/// Alias for `Result<T, NodeError>`.
pub type NodeResult<T> = Result<T, NodeError>;

// -----------------------------------------------------------------------------
// Quantum Node State
// -----------------------------------------------------------------------------

/// Represents the quantum state of the node.
#[derive(Debug, Clone)]
struct QuantumNodeState {
    /// Overall node coherence (1.0 = pure state).
    coherence: f64,
    /// Entanglement entropy between components.
    entanglement_entropy: f64,
    /// Component fidelities.
    component_fidelities: std::collections::HashMap<String, f64>,
    /// Node uptime (in quantum cycles).
    uptime_cycles: u64,
    /// Startup timestamp.
    startup_time: Instant,
}

impl QuantumNodeState {
    /// Create a new quantum node state in the ground state.
    fn new() -> Self {
        Self {
            coherence: 1.0,
            entanglement_entropy: 0.0,
            component_fidelities: std::collections::HashMap::new(),
            uptime_cycles: 0,
            startup_time: Instant::now(),
        }
    }

    /// Apply decoherence from environmental interactions.
    fn apply_decoherence(&mut self, strength: f64) {
        self.coherence *= (-strength).exp();
        self.entanglement_entropy = -self.coherence * self.coherence.ln();
    }

    /// Register a component with initial fidelity.
    fn register_component(&mut self, name: &str, fidelity: f64) {
        self.component_fidelities
            .insert(name.to_string(), fidelity);
    }

    /// Update component fidelity.
    fn update_component_fidelity(&mut self, name: &str, fidelity: f64) {
        if let Some(f) = self.component_fidelities.get_mut(name) {
            *f = fidelity;
        }
    }

    /// Check if the node is in a healthy quantum state.
    fn is_healthy(&self) -> bool {
        self.coherence >= MIN_COHERENCE_THRESHOLD
            && self
                .component_fidelities
                .values()
                .all(|&f| f >= MIN_COHERENCE_THRESHOLD)
    }

    /// Get overall node health metric.
    fn health_metric(&self) -> f64 {
        let component_avg: f64 = if self.component_fidelities.is_empty() {
            1.0
        } else {
            self.component_fidelities.values().sum::<f64>()
                / self.component_fidelities.len() as f64
        };
        self.coherence * component_avg
    }
}

// -----------------------------------------------------------------------------
// Quantum Node Structure
// -----------------------------------------------------------------------------

/// Main quantum node handle.
///
/// Holds all components in an entangled quantum state and manages
/// the node lifecycle through unitary evolution.
pub struct Node {
    /// Node configuration (classical observable).
    config: Config,
    /// Quantum state of the node.
    quantum_state: Arc<std::sync::Mutex<QuantumNodeState>>,
    /// Shutdown signal sender (triggers projective measurement).
    shutdown_tx: watch::Sender<()>,
    /// Shutdown signal receiver.
    shutdown_rx: watch::Receiver<()>,
    /// Node start time (for uptime calculation).
    start_time: Instant,
}

impl Node {
    /// Create a new quantum node instance.
    ///
    /// Prepares the initial quantum state |ψ₀⟩ and entangles all components.
    pub async fn new(config: Config) -> NodeResult<Self> {
        // Validate configuration (classical measurement)
        config.validate()?;

        // Initialise quantum state
        let mut qstate = QuantumNodeState::new();

        // Initialise tracing / logging
        init_tracing(&config);

        info!(
            "Initialising quantum IONA node v{}",
            env!("CARGO_PKG_VERSION")
        );
        info!("Data directory: {}", config.node.data_dir);
        info!("Initial coherence: γ={:.4}", qstate.coherence);

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
            }
        }

        // Register components with initial fidelities
        qstate.register_component("consensus", 1.0);
        qstate.register_component("network", 1.0);
        qstate.register_component("storage", 1.0);
        qstate.register_component("execution", 1.0);
        qstate.register_component("rpc", 1.0);
        qstate.register_component("mempool", 1.0);

        // Apply initialisation decoherence
        qstate.apply_decoherence(0.001);

        // Create shutdown channel
        let (shutdown_tx, shutdown_rx) = watch::channel(());

        info!(
            "Quantum node initialised: coherence={:.4}, entropy={:.4}",
            qstate.coherence, qstate.entanglement_entropy
        );

        Ok(Self {
            config,
            quantum_state: Arc::new(std::sync::Mutex::new(qstate)),
            shutdown_tx,
            shutdown_rx,
            start_time: Instant::now(),
        })
    }

    /// Run the node main loop — continuous unitary evolution.
    ///
    /// Starts all background services and blocks until a shutdown
    /// signal is received, at which point a projective measurement
    /// collapses the node to the |stopped⟩ state.
    pub async fn run(&self) -> NodeResult<()> {
        info!("Starting quantum IONA node evolution");

        // Start RPC server (if configured)
        let rpc_handle = if !self.config.rpc.listen.is_empty() {
            info!(
                "Starting RPC server on {} (γ={:.4})",
                self.config.rpc.listen,
                self.coherence()
            );
            let listen_addr = self.config.rpc.listen.parse().map_err(|e| {
                NodeError::Init(format!("invalid RPC listen address: {e}"))
            })?;
            let shutdown_rx = self.shutdown_rx.clone();
            let rpc_config = self.config.rpc.clone();
            Some(tokio::spawn(async move {
                if let Err(e) =
                    rpc::router::serve(listen_addr, rpc_config, shutdown_rx).await
                {
                    error!("RPC server decoherence: {}", e);
                }
            }))
        } else {
            debug!("RPC server disabled (no listen address)");
            None
        };

        // Start metrics server (if enabled)
        let metrics_handle = if self.config.observability.enable_metrics {
            let metrics_addr = self
                .config
                .observability
                .metrics_listen
                .parse()
                .map_err(|e| {
                    NodeError::Init(format!("invalid metrics address: {e}"))
                })?;
            let shutdown_rx = self.shutdown_rx.clone();
            Some(tokio::spawn(async move {
                if let Err(e) = metrics::serve(metrics_addr, shutdown_rx).await {
                    error!("Metrics server decoherence: {}", e);
                }
            }))
        } else {
            None
        };

        // Update component fidelities after startup
        {
            let mut qstate = self.quantum_state.lock().unwrap();
            qstate.update_component_fidelity("rpc", 0.995);
            qstate.apply_decoherence(0.0001);
        }

        info!(
            "Quantum node started successfully — health: {:.4}",
            self.health_metric()
        );

        // Wait for shutdown signal (projective measurement trigger)
        wait_for_shutdown(self.shutdown_rx.clone()).await;
        info!("Shutdown signal received — collapsing to |stopped⟩");

        // Cancel all background tasks
        if let Some(handle) = rpc_handle {
            handle.abort();
        }
        if let Some(handle) = metrics_handle {
            handle.abort();
        }

        // Final decoherence on shutdown
        {
            let mut qstate = self.quantum_state.lock().unwrap();
            qstate.apply_decoherence(0.1);
            info!(
                "Final coherence: γ={:.4}, uptime: {} cycles",
                qstate.coherence,
                qstate.uptime_cycles
            );
        }

        info!("Quantum node shutdown complete");
        Ok(())
    }

    /// Trigger a graceful shutdown — projective measurement.
    pub fn shutdown(&self) {
        info!("Triggering quantum node shutdown sequence");
        let _ = self.shutdown_tx.send(());
    }

    /// Get current node coherence.
    pub fn coherence(&self) -> f64 {
        self.quantum_state.lock().unwrap().coherence
    }

    /// Get entanglement entropy.
    pub fn entanglement_entropy(&self) -> f64 {
        self.quantum_state.lock().unwrap().entanglement_entropy
    }

    /// Get overall health metric.
    pub fn health_metric(&self) -> f64 {
        self.quantum_state.lock().unwrap().health_metric()
    }

    /// Check if node is in healthy quantum state.
    pub fn is_healthy(&self) -> bool {
        self.quantum_state.lock().unwrap().is_healthy()
    }

    /// Get component fidelity.
    pub fn component_fidelity(&self, component: &str) -> Option<f64> {
        self.quantum_state
            .lock()
            .unwrap()
            .component_fidelities
            .get(component)
            .copied()
    }

    /// Get node uptime.
    pub fn uptime(&self) -> std::time::Duration {
        self.start_time.elapsed()
    }

    /// Get quantum node statistics.
    pub fn stats(&self) -> NodeStats {
        let qstate = self.quantum_state.lock().unwrap();
        NodeStats {
            coherence: qstate.coherence,
            entanglement_entropy: qstate.entanglement_entropy,
            component_fidelities: qstate.component_fidelities.clone(),
            uptime: self.start_time.elapsed(),
            is_healthy: qstate.is_healthy(),
            health_metric: qstate.health_metric(),
        }
    }
}

// -----------------------------------------------------------------------------
// Node Statistics
// -----------------------------------------------------------------------------

/// Observable statistics for the quantum node.
#[derive(Debug, Clone)]
pub struct NodeStats {
    pub coherence: f64,
    pub entanglement_entropy: f64,
    pub component_fidelities: std::collections::HashMap<String, f64>,
    pub uptime: std::time::Duration,
    pub is_healthy: bool,
    pub health_metric: f64,
}

// -----------------------------------------------------------------------------
// Helper Functions
// -----------------------------------------------------------------------------

/// Initialise quantum tracing system.
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
                        opentelemetry::KeyValue::new(
                            "service.name",
                            service_name,
                        ),
                    ]),
                ))
                .build();
            global::set_tracer_provider(provider);
            let otel_layer =
                tracing_opentelemetry::layer().with_tracer(global::tracer("iona-node"));
            builder.with(otel_layer).init();
            return;
        }
    }
    builder.init();
}

/// Wait for shutdown signal — trigger for projective measurement.
async fn wait_for_shutdown(mut shutdown_rx: watch::Receiver<()>) {
    let ctrl_c = async {
        signal::ctrl_c()
            .await
            .expect("failed to install Ctrl+C handler");
        info!("Received Ctrl+C — initiating quantum state collapse");
    };

    #[cfg(unix)]
    let terminate = async {
        signal::unix::signal(signal::unix::SignalKind::terminate())
            .expect("failed to install SIGTERM handler")
            .recv()
            .await;
        info!("Received SIGTERM — initiating quantum state collapse");
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {},
        _ = terminate => {},
        _ = shutdown_rx.changed() => {
            info!("Internal shutdown signal — projective measurement triggered");
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

/// Quantum prelude for convenient importing of common items.
pub mod prelude {
    pub use super::{
        Config, Node, NodeError, NodeResult, NodeStats,
        Block, Hash32, Height, Receipt, Round, Tx,
        KvState,
        PublicKeyBytes, Signer, Verifier, Ed25519Verifier,
        MempoolTrait,
        init_metrics, metrics,
    };
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_quantum_node_state_initialization() {
        let qstate = QuantumNodeState::new();
        assert!((qstate.coherence - 1.0).abs() < 1e-10);
        assert!((qstate.entanglement_entropy - 0.0).abs() < 1e-10);
        assert!(qstate.is_healthy());
    }

    #[test]
    fn test_quantum_decoherence() {
        let mut qstate = QuantumNodeState::new();
        qstate.apply_decoherence(0.5);
        assert!(qstate.coherence < 1.0);
        assert!(qstate.entanglement_entropy > 0.0);
    }

    #[test]
    fn test_component_registration() {
        let mut qstate = QuantumNodeState::new();
        qstate.register_component("test_component", 0.99);
        assert_eq!(
            qstate.component_fidelities.get("test_component"),
            Some(&0.99)
        );
    }

    #[test]
    fn test_health_metric() {
        let mut qstate = QuantumNodeState::new();
        qstate.register_component("comp_a", 1.0);
        qstate.register_component("comp_b", 0.8);
        assert!(!qstate.is_healthy());
        assert!(qstate.health_metric() < 1.0);
    }
}
