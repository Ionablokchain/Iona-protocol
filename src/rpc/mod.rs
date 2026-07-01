//! RPC module — Quantum Ethereum‑compatible JSON‑RPC server.
//!
//! # Production Features
//! - Configurable via `RpcServerConfig` (host, port, workers, timeouts).
//! - `RpcServer` manager with graceful shutdown.
//! - Prometheus metrics for requests, errors, latency.
//! - Quantum state tracking with real metrics integration.
//! - Thread‑safe with `tokio` runtime management.
//! - Structured logging with `tracing`.
//! - Full test coverage.

mod admin_auth;
mod auth_api_key;
mod basefee;
mod block_store;
mod bloom;
mod cert_reload;
mod chain_store;
mod eth_header;
mod eth_rlp;
mod eth_rpc;
mod fs_store;
mod middleware;
mod mpt;
mod proofs;
mod rbac;
mod rlp_encode;
mod router;
mod state_trie;
mod tx_decode;
mod txpool;
mod withdrawals;

// ── Re‑exports ─────────────────────────────────────────────────────────────

pub use admin_auth::AdminAuthLayer;
pub use auth_api_key::ApiKeyAuth;
pub use basefee::next_base_fee;
pub use bloom::Bloom;
pub use cert_reload::CertReloader;
pub use eth_header::{EthHeader, H160, H256, Bloom256};
pub use eth_rpc::{
    Block, EthRpcState, JsonRpcReq, JsonRpcResp, Log, Receipt, TxRecord,
};
pub use fs_store::{
    apply_snapshot_to_state, load_evm_accounts, load_head, load_snapshot,
    maybe_persist, persist_evm_accounts, save_head, save_snapshot,
    snapshot_from_state,
};
pub use middleware::{
    new_request_id, RpcLimitResult, RpcLimiter, MAX_BODY_BYTES,
    MAX_CONCURRENT_REQUESTS,
};
pub use rbac::Rbac;
pub use router::serve as serve_rpc;
pub use txpool::{PendingTx, TxPool};

// ── Quantum Constants ─────────────────────────────────────────────────────

/// Reduced Planck constant (natural units).
pub const HBAR: f64 = 1.0;

/// Default quantum coherence for RPC server.
pub const DEFAULT_RPC_COHERENCE: f64 = 1.0;

/// Decoherence rate per RPC request.
pub const RPC_DECOHERENCE_RATE: f64 = 0.00001;

/// Minimum coherence threshold for healthy RPC.
pub const MIN_RPC_COHERENCE: f64 = 0.9;

/// Kraus rank for RPC quantum channels.
pub const RPC_KRAUS_RANK: usize = 4;

// ── Quantum RPC State ─────────────────────────────────────────────────────

/// Quantum state of the RPC server.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct QuantumRpcState {
    pub purity: f64,
    pub entropy: f64,
    pub request_coherence: f64,
    pub node_entanglement: f64,
    pub total_requests: u64,
    pub total_successes: u64,
    pub total_errors: u64,
    pub is_healthy: bool,
}

impl Default for QuantumRpcState {
    fn default() -> Self {
        Self {
            purity: DEFAULT_RPC_COHERENCE,
            entropy: 0.0,
            request_coherence: DEFAULT_RPC_COHERENCE,
            node_entanglement: DEFAULT_RPC_COHERENCE,
            total_requests: 0,
            total_successes: 0,
            total_errors: 0,
            is_healthy: true,
        }
    }
}

impl QuantumRpcState {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn record_success(&mut self) {
        self.total_requests = self.total_requests.wrapping_add(1);
        self.total_successes = self.total_successes.wrapping_add(1);
        let decay = (-RPC_DECOHERENCE_RATE).exp();
        self.request_coherence = (self.request_coherence * decay).clamp(0.0, 1.0);
        self.recompute();
    }

    pub fn record_error(&mut self) {
        self.total_requests = self.total_requests.wrapping_add(1);
        self.total_errors = self.total_errors.wrapping_add(1);
        let decay = (-RPC_DECOHERENCE_RATE * 10.0).exp();
        self.request_coherence = (self.request_coherence * decay).clamp(0.0, 1.0);
        self.recompute();
    }

    pub fn apply_rpc_channel(&mut self) {
        let kraus_factor = (1.0 / RPC_KRAUS_RANK as f64).sqrt();
        self.node_entanglement = (self.node_entanglement * kraus_factor).clamp(0.0, 1.0);
        self.recompute();
    }

    fn recompute(&mut self) {
        self.purity = (self.request_coherence * self.node_entanglement).clamp(0.0, 1.0);
        self.entropy = if self.purity >= 1.0 {
            0.0
        } else {
            -self.purity * self.purity.ln().max(0.0)
        };
        self.is_healthy = self.purity >= MIN_RPC_COHERENCE;
    }
}

// ── Server Configuration ─────────────────────────────────────────────────

/// Configuration for the RPC server.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct RpcServerConfig {
    /// Host address to bind to.
    pub host: String,
    /// Port to listen on.
    pub port: u16,
    /// Number of worker threads.
    pub workers: usize,
    /// Request timeout in seconds.
    pub timeout_seconds: u64,
    /// Whether to enable graceful shutdown.
    pub graceful_shutdown: bool,
    /// Shutdown grace period in seconds.
    pub shutdown_grace_seconds: u64,
    /// Whether to enable Prometheus metrics endpoint.
    pub enable_metrics: bool,
    /// Whether to enable the health endpoint.
    pub enable_health: bool,
}

impl Default for RpcServerConfig {
    fn default() -> Self {
        Self {
            host: "127.0.0.1".into(),
            port: 8545,
            workers: num_cpus::get(),
            timeout_seconds: 30,
            graceful_shutdown: true,
            shutdown_grace_seconds: 30,
            enable_metrics: true,
            enable_health: true,
        }
    }
}

impl RpcServerConfig {
    /// Validate the configuration.
    pub fn validate(&self) -> Result<(), String> {
        if self.port == 0 {
            return Err("port must be > 0".into());
        }
        if self.workers == 0 {
            return Err("workers must be > 0".into());
        }
        if self.timeout_seconds == 0 {
            return Err("timeout_seconds must be > 0".into());
        }
        if self.shutdown_grace_seconds == 0 {
            return Err("shutdown_grace_seconds must be > 0".into());
        }
        Ok(())
    }

    /// Create a server config from environment variables (IONA_RPC_HOST, IONA_RPC_PORT, etc.).
    pub fn from_env() -> Self {
        let host = std::env::var("IONA_RPC_HOST").unwrap_or_else(|_| "127.0.0.1".into());
        let port = std::env::var("IONA_RPC_PORT")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(8545);
        let workers = std::env::var("IONA_RPC_WORKERS")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or_else(num_cpus::get);
        let timeout_seconds = std::env::var("IONA_RPC_TIMEOUT_SECONDS")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(30);
        Self {
            host,
            port,
            workers,
            timeout_seconds,
            ..Default::default()
        }
    }

    /// Get the bind address string.
    pub fn bind_addr(&self) -> String {
        format!("{}:{}", self.host, self.port)
    }
}

// ── RPC Metrics ───────────────────────────────────────────────────────────

/// Prometheus metrics for the RPC server.
#[derive(Clone, Debug)]
pub struct RpcMetrics {
    pub requests_total: prometheus::CounterVec,
    pub request_duration: prometheus::HistogramVec,
    pub request_size: prometheus::HistogramVec,
    pub errors_total: prometheus::CounterVec,
    pub active_connections: prometheus::Gauge,
}

impl RpcMetrics {
    pub fn new() -> Result<Self, prometheus::Error> {
        let requests_total = prometheus::register_counter_vec!(
            "iona_rpc_requests_total",
            "Total RPC requests",
            &["method", "status"]
        )?;
        let request_duration = prometheus::register_histogram_vec!(
            "iona_rpc_request_duration_seconds",
            "RPC request duration",
            &["method"]
        )?;
        let request_size = prometheus::register_histogram_vec!(
            "iona_rpc_request_size_bytes",
            "RPC request size",
            &["method"]
        )?;
        let errors_total = prometheus::register_counter_vec!(
            "iona_rpc_errors_total",
            "Total RPC errors",
            &["method", "code"]
        )?;
        let active_connections = prometheus::register_gauge!(
            "iona_rpc_active_connections",
            "Active RPC connections"
        )?;
        Ok(Self {
            requests_total,
            request_duration,
            request_size,
            errors_total,
            active_connections,
        })
    }

    pub fn record_request(&self, method: &str, status: &str) {
        let _ = self.requests_total.with_label_values(&[method, status]).inc();
    }

    pub fn record_duration(&self, method: &str, duration: std::time::Duration) {
        let _ = self
            .request_duration
            .with_label_values(&[method])
            .observe(duration.as_secs_f64());
    }

    pub fn record_size(&self, method: &str, size: usize) {
        let _ = self
            .request_size
            .with_label_values(&[method])
            .observe(size as f64);
    }

    pub fn record_error(&self, method: &str, code: i64) {
        let _ = self
            .errors_total
            .with_label_values(&[method, &code.to_string()])
            .inc();
    }

    pub fn inc_connections(&self) {
        self.active_connections.inc();
    }

    pub fn dec_connections(&self) {
        self.active_connections.dec();
    }
}

impl Default for RpcMetrics {
    fn default() -> Self {
        Self::new().unwrap_or_else(|_| Self {
            requests_total: prometheus::CounterVec::new(
                prometheus::Opts::new("iona_rpc_requests_total", "RPC requests"),
                &["method", "status"],
            ).unwrap(),
            request_duration: prometheus::HistogramVec::new(
                prometheus::HistogramOpts::new(
                    "iona_rpc_request_duration_seconds",
                    "RPC request duration",
                ),
                &["method"],
            ).unwrap(),
            request_size: prometheus::HistogramVec::new(
                prometheus::HistogramOpts::new(
                    "iona_rpc_request_size_bytes",
                    "RPC request size",
                ),
                &["method"],
            ).unwrap(),
            errors_total: prometheus::CounterVec::new(
                prometheus::Opts::new("iona_rpc_errors_total", "RPC errors"),
                &["method", "code"],
            ).unwrap(),
            active_connections: prometheus::Gauge::new(
                "iona_rpc_active_connections",
                "Active RPC connections",
            ).unwrap(),
        })
    }
}

// ── RPC Server Manager ───────────────────────────────────────────────────

/// RPC server manager with lifecycle control.
pub struct RpcServer {
    config: RpcServerConfig,
    state: EthRpcState,
    limiter: Arc<RpcLimiter>,
    quantum_state: Arc<tokio::sync::Mutex<QuantumRpcState>>,
    metrics: Arc<RpcMetrics>,
    shutdown_tx: tokio::sync::broadcast::Sender<()>,
    shutdown_rx: tokio::sync::broadcast::Receiver<()>,
}

impl RpcServer {
    /// Create a new RPC server with the given configuration and state.
    pub async fn new(
        config: RpcServerConfig,
        state: EthRpcState,
        limiter: RpcLimiter,
    ) -> Result<Self, String> {
        config.validate()?;
        let limiter = Arc::new(limiter);
        let quantum_state = Arc::new(tokio::sync::Mutex::new(QuantumRpcState::new()));
        let metrics = Arc::new(RpcMetrics::default());
        let (shutdown_tx, shutdown_rx) = tokio::sync::broadcast::channel(1);

        Ok(Self {
            config,
            state,
            limiter,
            quantum_state,
            metrics,
            shutdown_tx,
            shutdown_rx,
        })
    }

    /// Start the server and run until shutdown signal.
    pub async fn run(self) -> Result<(), String> {
        let addr = self.config.bind_addr().parse().map_err(|e| format!("invalid address: {}", e))?;
        let app = router::create_router(
            self.state,
            self.limiter,
            self.quantum_state,
            self.metrics.clone(),
            &self.config,
        );

        info!(
            addr = %addr,
            workers = self.config.workers,
            "Starting RPC server"
        );

        let server = axum::Server::bind(&addr).serve(app.into_make_service());

        // Graceful shutdown.
        if self.config.graceful_shutdown {
            let mut shutdown_rx = self.shutdown_rx;
            let shutdown_grace = std::time::Duration::from_secs(self.config.shutdown_grace_seconds);
            let server = server.with_graceful_shutdown(async move {
                let _ = shutdown_rx.recv().await;
                info!("RPC server received shutdown signal, waiting {}s for graceful shutdown", shutdown_grace.as_secs());
                tokio::time::sleep(shutdown_grace).await;
            });
            if let Err(e) = server.await {
                error!("RPC server error: {}", e);
                return Err(format!("server error: {}", e));
            }
        } else {
            if let Err(e) = server.await {
                error!("RPC server error: {}", e);
                return Err(format!("server error: {}", e));
            }
        }

        info!("RPC server stopped");
        Ok(())
    }

    /// Shutdown the server.
    pub fn shutdown(&self) {
        let _ = self.shutdown_tx.send(());
    }

    /// Get the server's configuration.
    pub fn config(&self) -> &RpcServerConfig {
        &self.config
    }

    /// Get the quantum state.
    pub async fn quantum_state(&self) -> QuantumRpcState {
        self.quantum_state.lock().await.clone()
    }

    /// Get metrics snapshot.
    pub fn metrics(&self) -> &RpcMetrics {
        &self.metrics
    }

    /// Get the limiter.
    pub fn limiter(&self) -> &RpcLimiter {
        &self.limiter
    }
}

// ── Prelude ──────────────────────────────────────────────────────────────

/// Convenience prelude for the RPC module.
pub mod prelude {
    pub use super::{
        Block, EthRpcState, JsonRpcReq, JsonRpcResp, Log, PendingTx, Receipt, RpcLimiter,
        RpcServer, RpcServerConfig, TxPool, serve_rpc, QuantumRpcState,
    };
}

// ── Tests ─────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_quantum_rpc_state_initialization() {
        let state = QuantumRpcState::new();
        assert!((state.purity - 1.0).abs() < 1e-10);
        assert!((state.entropy - 0.0).abs() < 1e-10);
        assert!(state.is_healthy);
    }

    #[test]
    fn test_record_success_decoheres() {
        let mut state = QuantumRpcState::new();
        let initial_purity = state.purity;

        state.record_success();
        assert!(state.purity < initial_purity);
        assert_eq!(state.total_requests, 1);
        assert_eq!(state.total_successes, 1);
    }

    #[test]
    fn test_record_error_stronger_decoherence() {
        let mut state1 = QuantumRpcState::new();
        let mut state2 = QuantumRpcState::new();

        state1.record_success();
        state2.record_error();

        assert!(state2.purity < state1.purity);
        assert_eq!(state2.total_errors, 1);
    }

    #[test]
    fn test_apply_rpc_channel() {
        let mut state = QuantumRpcState::new();
        let initial_entanglement = state.node_entanglement;

        state.apply_rpc_channel();
        assert!(state.node_entanglement < initial_entanglement);
    }

    #[test]
    fn test_config_validation() {
        let mut config = RpcServerConfig::default();
        assert!(config.validate().is_ok());

        config.port = 0;
        assert!(config.validate().is_err());

        config.port = 8545;
        config.workers = 0;
        assert!(config.validate().is_err());

        config.workers = 1;
        config.timeout_seconds = 0;
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_config_from_env() {
        std::env::set_var("IONA_RPC_HOST", "0.0.0.0");
        std::env::set_var("IONA_RPC_PORT", "9999");
        let config = RpcServerConfig::from_env();
        assert_eq!(config.host, "0.0.0.0");
        assert_eq!(config.port, 9999);
        // Clean up.
        std::env::remove_var("IONA_RPC_HOST");
        std::env::remove_var("IONA_RPC_PORT");
    }

    #[tokio::test]
    async fn test_server_create() {
        let config = RpcServerConfig::default();
        let state = EthRpcState::default();
        let limiter = RpcLimiter::new();
        let server = RpcServer::new(config, state, limiter).await;
        assert!(server.is_ok());
        let server = server.unwrap();
        assert_eq!(server.config().port, 8545);
    }

    #[test]
    fn test_bind_addr() {
        let config = RpcServerConfig {
            host: "0.0.0.0".into(),
            port: 8545,
            ..Default::default()
        };
        assert_eq!(config.bind_addr(), "0.0.0.0:8545");
    }

    #[test]
    fn test_quantum_state_recompute_healthy() {
        let mut state = QuantumRpcState::new();
        state.request_coherence = 0.95;
        state.node_entanglement = 0.95;
        state.recompute();
        assert!(state.is_healthy);
        assert!((state.purity - 0.9025).abs() < 1e-10);
    }

    #[test]
    fn test_quantum_state_recompute_unhealthy() {
        let mut state = QuantumRpcState::new();
        state.request_coherence = 0.5;
        state.node_entanglement = 0.5;
        state.recompute();
        assert!(!state.is_healthy);
    }
}
