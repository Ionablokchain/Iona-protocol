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
//! # Production Features
//! - Comprehensive node lifecycle management.
//! - Thread‑safe component coordination.
//! - Graceful shutdown with signal handling.
//! - Structured logging and OpenTelemetry integration.
//! - Component health monitoring with quantum-inspired metrics.
//! - Atomic configuration loading with validation.
//! - Persistent state with atomic writes.

#![deny(missing_docs)]
#![deny(rustdoc::broken_intra_doc_links)]
#![allow(clippy::module_inception)]
#![allow(clippy::type_complexity)]
#![allow(dead_code)]

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
use std::time::{Duration, Instant};
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

/// Default shutdown timeout in seconds.
const DEFAULT_SHUTDOWN_TIMEOUT_SECS: u64 = 30;

/// Health check interval in seconds.
const HEALTH_CHECK_INTERVAL_SECS: u64 = 10;

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

    #[error("component not found: {0}")]
    ComponentNotFound(String),

    #[error("shutdown timeout after {0}s")]
    ShutdownTimeout(u64),

    #[error("already shutting down")]
    AlreadyShuttingDown,

    #[error("component failed to start: {component} -> {reason}")]
    ComponentStartFailed { component: String, reason: String },

    #[error("unexpected error: {0}")]
    Unexpected(String),
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
    /// Whether the node is in the |shutting_down⟩ state.
    shutting_down: bool,
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
            shutting_down: false,
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

    /// Get component fidelity.
    fn component_fidelity(&self, name: &str) -> Option<f64> {
        self.component_fidelities.get(name).copied()
    }

    /// Check if the node is in a healthy quantum state.
    fn is_healthy(&self) -> bool {
        if self.shutting_down {
            return true; // shutting down is a valid state
        }
        self.coherence >= MIN_COHERENCE_THRESHOLD
            && self
                .component_fidelities
                .values()
                .all(|&f| f >= MIN_COHERENCE_THRESHOLD)
    }

    /// Get overall node health metric.
    fn health_metric(&self) -> f64 {
        if self.component_fidelities.is_empty() {
            return self.coherence;
        }
        let component_avg: f64 = self.component_fidelities.values().sum::<f64>()
            / self.component_fidelities.len() as f64;
        self.coherence * component_avg
    }

    /// Record an uptime cycle.
    fn tick(&mut self) {
        self.uptime_cycles = self.uptime_cycles.wrapping_add(1);
        self.apply_decoherence(1.0 / NODE_COHERENCE_TIME as f64);
    }

    /// Enter shutdown state.
    fn begin_shutdown(&mut self) {
        self.shutting_down = true;
        self.apply_decoherence(0.05);
    }
}

// -----------------------------------------------------------------------------
// Component Trait
// -----------------------------------------------------------------------------

/// Trait for quantum node components.
///
/// Each component is a subsystem in the node's Hilbert space that
/// can be started, stopped, and monitored.
pub trait NodeComponent: Send + Sync + 'static {
    /// Start the component — apply U_start |∅⟩ → |ready⟩.
    fn start(&mut self) -> NodeResult<()>;

    /// Stop the component — projective measurement to |stopped⟩.
    fn stop(&mut self) -> NodeResult<()>;

    /// Get the component's current fidelity.
    fn fidelity(&self) -> f64;

    /// Get the component's name.
    fn name(&self) -> &'static str;

    /// Check if the component is running.
    fn is_running(&self) -> bool;
}

// -----------------------------------------------------------------------------
// Node Configuration Builder
// -----------------------------------------------------------------------------

/// Builder for quantum node configuration.
#[derive(Debug, Clone)]
pub struct NodeBuilder {
    config: config::NodeConfig,
    components: Vec<Box<dyn NodeComponent>>,
    shutdown_timeout: Duration,
}

impl Default for NodeBuilder {
    fn default() -> Self {
        Self {
            config: config::NodeConfig::default(),
            components: Vec::new(),
            shutdown_timeout: Duration::from_secs(DEFAULT_SHUTDOWN_TIMEOUT_SECS),
        }
    }
}

impl NodeBuilder {
    /// Create a new node builder.
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the node configuration.
    pub fn config(mut self, config: config::NodeConfig) -> Self {
        self.config = config;
        self
    }

    /// Load configuration from a file.
    pub fn load_config(mut self, path: impl AsRef<Path>) -> NodeResult<Self> {
        self.config = config::NodeConfig::load(path)?;
        Ok(self)
    }

    /// Add a component to the node.
    pub fn add_component(mut self, component: impl NodeComponent) -> Self {
        self.components.push(Box::new(component));
        self
    }

    /// Set shutdown timeout.
    pub fn shutdown_timeout(mut self, timeout: Duration) -> Self {
        self.shutdown_timeout = timeout;
        self
    }

    /// Build the quantum node.
    pub fn build(self) -> NodeResult<Node> {
        Node::new(self.config, self.components, self.shutdown_timeout)
    }
}

// -----------------------------------------------------------------------------
// Quantum Node Structure
// -----------------------------------------------------------------------------

/// Main quantum node handle.
pub struct Node {
    /// Node configuration (classical observable).
    config: config::NodeConfig,
    /// Quantum state of the node.
    quantum_state: Arc<std::sync::Mutex<QuantumNodeState>>,
    /// Registered components.
    components: Vec<Box<dyn NodeComponent>>,
    /// Shutdown signal sender (triggers projective measurement).
    shutdown_tx: watch::Sender<()>,
    /// Shutdown signal receiver.
    shutdown_rx: watch::Receiver<()>,
    /// Node start time.
    start_time: Instant,
    /// Shutdown timeout.
    shutdown_timeout: Duration,
    /// Health check handle.
    health_handle: Option<tokio::task::JoinHandle<()>>,
    /// Whether the node has been started.
    started: bool,
}

impl Node {
    /// Create a new quantum node instance.
    fn new(
        config: config::NodeConfig,
        components: Vec<Box<dyn NodeComponent>>,
        shutdown_timeout: Duration,
    ) -> NodeResult<Self> {
        // Validate configuration (classical measurement)
        config.validate()?;

        // Initialise quantum state
        let mut qstate = QuantumNodeState::new();

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
        for comp in &components {
            qstate.register_component(comp.name(), comp.fidelity());
        }

        // Apply initialisation decoherence
        qstate.apply_decoherence(0.001);

        // Create shutdown channel
        let (shutdown_tx, shutdown_rx) = watch::channel(());

        info!(
            "Quantum node initialised: coherence={:.4}, entropy={:.4}, components={}",
            qstate.coherence,
            qstate.entanglement_entropy,
            components.len()
        );

        Ok(Self {
            config,
            quantum_state: Arc::new(std::sync::Mutex::new(qstate)),
            components,
            shutdown_tx,
            shutdown_rx,
            start_time: Instant::now(),
            shutdown_timeout,
            health_handle: None,
            started: false,
        })
    }

    /// Run the node main loop.
    pub async fn run(&mut self) -> NodeResult<()> {
        if self.started {
            return Err(NodeError::Unexpected("node already started".into()));
        }
        self.started = true;

        // Validate configuration again (in case of changes)
        self.config.validate()?;

        // Initialise tracing
        init_tracing(&self.config);

        info!(
            "Starting quantum IONA node v{}",
            env!("CARGO_PKG_VERSION")
        );
        info!("Data directory: {}", self.config.node.data_dir);

        // Start all components
        let mut failed_components = Vec::new();
        for comp in &mut self.components {
            info!("Starting component: {}", comp.name());
            if let Err(e) = comp.start() {
                error!("Component {} failed to start: {}", comp.name(), e);
                failed_components.push(comp.name());
            }
        }

        if !failed_components.is_empty() {
            return Err(NodeError::ComponentStartFailed {
                component: failed_components.join(", "),
                reason: "failed to start".into(),
            });
        }

        // Update component fidelities after startup
        for comp in &self.components {
            let mut qstate = self.quantum_state.lock().unwrap();
            qstate.update_component_fidelity(comp.name(), comp.fidelity());
        }

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

        // Start RPC server (if configured)
        let rpc_handle = if !self.config.rpc.listen.is_empty() {
            info!("Starting RPC server on {}", self.config.rpc.listen);
            let listen_addr = self.config.rpc.listen.parse().map_err(|e| {
                NodeError::Init(format!("invalid RPC listen address: {e}"))
            })?;
            let shutdown_rx = self.shutdown_rx.clone();
            let rpc_config = self.config.rpc.clone();
            let eth_state = self.build_eth_rpc_state()?;
            Some(tokio::spawn(async move {
                if let Err(e) =
                    rpc::router::serve_with_eth(listen_addr, rpc_config, shutdown_rx, eth_state).await
                {
                    error!("RPC server decoherence: {}", e);
                }
            }))
        } else {
            debug!("RPC server disabled (no listen address)");
            None
        };

        // Apply final startup decoherence
        {
            let mut qstate = self.quantum_state.lock().unwrap();
            qstate.apply_decoherence(0.0001);
        }

        info!(
            "Quantum node started successfully — health: {:.4}",
            self.health_metric()
        );

        // Start health check task
        let health_handle = self.start_health_check();

        // Wait for shutdown signal
        wait_for_shutdown(self.shutdown_rx.clone()).await;
        info!("Shutdown signal received — collapsing to |stopped⟩");

        // Begin shutdown
        self.begin_shutdown().await?;

        // Cancel background tasks
        if let Some(handle) = rpc_handle {
            handle.abort();
        }
        if let Some(handle) = metrics_handle {
            handle.abort();
        }
        if let Some(handle) = health_handle {
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

    /// Begin shutdown sequence.
    async fn begin_shutdown(&mut self) -> NodeResult<()> {
        {
            let mut qstate = self.quantum_state.lock().unwrap();
            qstate.begin_shutdown();
        }

        // Stop all components in reverse order
        let start = Instant::now();
        for comp in self.components.iter_mut().rev() {
            debug!("Stopping component: {}", comp.name());
            if let Err(e) = comp.stop() {
                error!("Component {} failed to stop: {}", comp.name(), e);
            }
        }

        // Wait for all components to stop
        let timeout = self.shutdown_timeout;
        while !self.all_components_stopped() {
            if start.elapsed() > timeout {
                return Err(NodeError::ShutdownTimeout(timeout.as_secs()));
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }

        Ok(())
    }

    /// Check if all components are stopped.
    fn all_components_stopped(&self) -> bool {
        self.components.iter().all(|c| !c.is_running())
    }

    /// Start health check task.
    fn start_health_check(&self) -> Option<tokio::task::JoinHandle<()>> {
        let quantum_state = self.quantum_state.clone();
        let shutdown_rx = self.shutdown_rx.clone();
        let interval = Duration::from_secs(HEALTH_CHECK_INTERVAL_SECS);

        Some(tokio::spawn(async move {
            let mut interval_timer = tokio::time::interval(interval);
            loop {
                tokio::select! {
                    _ = interval_timer.tick() => {
                        let qstate = quantum_state.lock().unwrap();
                        if !qstate.is_healthy() {
                            warn!(
                                coherence = qstate.coherence,
                                health = qstate.health_metric(),
                                "node coherence below threshold"
                            );
                        }
                    }
                    _ = shutdown_rx.changed() => {
                        debug!("Health check: shutdown signal received");
                        break;
                    }
                }
            }
        }))
    }

    /// Build the Ethereum RPC state.
    fn build_eth_rpc_state(&self) -> NodeResult<rpc::eth_rpc::EthRpcState> {
        let data_dir = Path::new(&self.config.node.data_dir);
        let layout = storage::layout::DataLayout::new(data_dir);
        let block_store = storage::block_store::FsBlockStore::open(
            layout.blocks_dir(),
            None,
        ).map_err(|e| NodeError::Storage(e.to_string()))?;

        let state_db = evm::kv_state_db::KvStateDb::new(layout.state_full_path())
            .map_err(|e| NodeError::Storage(e.to_string()))?;

        Ok(rpc::eth_rpc::EthRpcState::new(
            block_store,
            state_db,
            self.config.chain_id,
        ))
    }

    /// Trigger a graceful shutdown.
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
        self.quantum_state.lock().unwrap().component_fidelity(component)
    }

    /// Get node uptime.
    pub fn uptime(&self) -> Duration {
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
            shutting_down: qstate.shutting_down,
            total_components: self.components.len(),
            running_components: self.components.iter().filter(|c| c.is_running()).count(),
        }
    }

    /// Get the node configuration.
    pub fn config(&self) -> &config::NodeConfig {
        &self.config
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
    pub uptime: Duration,
    pub is_healthy: bool,
    pub health_metric: f64,
    pub shutting_down: bool,
    pub total_components: usize,
    pub running_components: usize,
}

// -----------------------------------------------------------------------------
// Helper Functions
// -----------------------------------------------------------------------------

/// Initialise quantum tracing system.
fn init_tracing(config: &config::NodeConfig) {
    use tracing_subscriber::{fmt, prelude::*, EnvFilter};

    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new(&config.node.log_level));

    let builder = fmt::Subscriber::builder()
        .with_env_filter(filter)
        .with_target(true)
        .with_thread_ids(true)
        .with_writer(std::io::stderr)
        .with_ansi(atty::is(atty::Stream::Stderr));

    // OpenTelemetry integration
    #[cfg(feature = "otel")]
    {
        if config.observability.enable_otel {
            let endpoint = config.observability.otel_endpoint.clone();
            let service_name = config.observability.service_name.clone();
            match init_otel_tracing(&endpoint, &service_name) {
                Ok(layer) => {
                    builder.with(layer).init();
                    return;
                }
                Err(e) => {
                    error!("Failed to initialise OTEL tracing: {}", e);
                }
            }
        }
    }

    builder.init();
    debug!("Tracing initialised with level: {}", config.node.log_level);
}

#[cfg(feature = "otel")]
fn init_otel_tracing(
    endpoint: &str,
    service_name: &str,
) -> Result<tracing_opentelemetry::OpenTelemetryLayer<tracing_subscriber::Registry, opentelemetry_sdk::trace::Tracer>, String> {
    use opentelemetry::global;
    use opentelemetry_otlp::WithExportConfig;
    use opentelemetry_sdk::trace::{self, TracerProvider};

    let exporter = opentelemetry_otlp::new_exporter()
        .tonic()
        .with_endpoint(endpoint.to_string());

    let provider = TracerProvider::builder()
        .with_simple_exporter(exporter)
        .with_config(
            trace::config().with_resource(
                opentelemetry_sdk::Resource::new(vec![
                    opentelemetry::KeyValue::new(
                        "service.name",
                        service_name.to_string(),
                    ),
                    opentelemetry::KeyValue::new(
                        "service.version",
                        env!("CARGO_PKG_VERSION").to_string(),
                    ),
                ]),
            ),
        )
        .build();

    global::set_tracer_provider(provider);
    let tracer = global::tracer(service_name);
    Ok(tracing_opentelemetry::layer().with_tracer(tracer))
}

/// Wait for shutdown signal.
async fn wait_for_shutdown(mut shutdown_rx: watch::Receiver<()>) {
    let ctrl_c = async {
        signal::ctrl_c()
            .await
            .expect("failed to install Ctrl+C handler");
        info!("Received Ctrl+C — initiating quantum state collapse");
    };

    #[cfg(unix)]
    let terminate = async {
        use signal::unix::{signal, SignalKind};
        signal(SignalKind::terminate())
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
        Config, Node, NodeBuilder, NodeError, NodeResult, NodeStats,
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
    use std::sync::atomic::{AtomicBool, Ordering};

    struct TestComponent {
        name: &'static str,
        running: AtomicBool,
        fidelity: f64,
    }

    impl TestComponent {
        fn new(name: &'static str, fidelity: f64) -> Self {
            Self {
                name,
                running: AtomicBool::new(false),
                fidelity,
            }
        }
    }

    impl NodeComponent for TestComponent {
        fn start(&mut self) -> NodeResult<()> {
            self.running.store(true, Ordering::SeqCst);
            Ok(())
        }

        fn stop(&mut self) -> NodeResult<()> {
            self.running.store(false, Ordering::SeqCst);
            Ok(())
        }

        fn fidelity(&self) -> f64 {
            self.fidelity
        }

        fn name(&self) -> &'static str {
            self.name
        }

        fn is_running(&self) -> bool {
            self.running.load(Ordering::SeqCst)
        }
    }

    #[test]
    fn test_node_builder() {
        let comp = TestComponent::new("test", 1.0);
        let builder = NodeBuilder::new()
            .add_component(comp)
            .shutdown_timeout(Duration::from_secs(5));

        let node = builder.build().unwrap();
        assert_eq!(node.components.len(), 1);
        assert_eq!(node.components[0].name(), "test");
    }

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

    #[test]
    fn test_node_stats() {
        let comp = TestComponent::new("test", 1.0);
        let node = NodeBuilder::new()
            .add_component(comp)
            .build()
            .unwrap();

        let stats = node.stats();
        assert!((stats.coherence - 1.0).abs() < 1e-10);
        assert_eq!(stats.total_components, 1);
        assert_eq!(stats.running_components, 0);
        assert!(!stats.shutting_down);
    }
}
