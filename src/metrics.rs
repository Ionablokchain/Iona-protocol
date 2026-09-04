//! Quantum Prometheus metrics for IONA production node.
//!
//! # Quantum Observability Model
//!
//! Metrics are quantum observables — Hermitian operators whose eigenvalues
//! correspond to measurable quantities. Each metric is a projective
//! measurement in the computational basis of the node's Hilbert space.
//!
//! # Production Features
//! - Configurable metrics with `MetricsConfig`.
//! - Conditional metric registration (enable/disable groups).
//! - Support for labeled metrics (via `prometheus::*Vec`).
//! - Built‑in HTTP server for `/metrics` endpoint.
//! - OpenTelemetry integration (feature‑gated).
//! - Thread‑safe global metrics access.
//! - Comprehensive documentation and tests.

use prometheus::{
    core::{Collector, GenericCounter, GenericGauge, GenericHistogram},
    Encoder, Gauge, Histogram, HistogramOpts, IntCounter, IntGauge, Opts, Registry, TextEncoder,
};
use std::net::SocketAddr;
use std::sync::OnceLock;
use std::time::Duration;
use thiserror::Error;
use tracing::{debug, error, info, warn};

// -----------------------------------------------------------------------------
// Quantum Constants
// -----------------------------------------------------------------------------

/// Prefix for all IONA metrics (quantum observable namespace).
pub const METRIC_PREFIX: &str = "iona";

/// Reduced Planck constant (natural units).
const HBAR: f64 = 1.0;

/// Measurement decoherence per scrape.
const MEASUREMENT_DECOHERENCE: f64 = 0.00001;

/// Default HTTP server timeout (seconds).
const DEFAULT_HTTP_TIMEOUT_SECS: u64 = 10;

/// Default bucket values for block time (milliseconds).
const BLOCK_TIME_BUCKETS_MS: &[f64] = &[
    10.0, 25.0, 50.0, 100.0, 200.0, 500.0, 1000.0, 2000.0, 5000.0,
];

/// Default bucket values for transactions per block.
const TXS_PER_BLOCK_BUCKETS: &[f64] = &[
    0.0, 1.0, 10.0, 50.0, 100.0, 500.0, 1000.0, 4096.0,
];

/// Default bucket values for gas per block.
const GAS_PER_BLOCK_BUCKETS: &[f64] = &[
    0.0, 100_000.0, 1_000_000.0, 10_000_000.0, 30_000_000.0, 86_000_000.0,
];

/// Default bucket values for finality latency (milliseconds).
const FINALITY_LATENCY_BUCKETS_MS: &[f64] = &[
    10.0, 25.0, 50.0, 100.0, 200.0, 500.0, 1000.0, 2000.0,
];

/// Default bucket values for RPC request duration (seconds).
const RPC_DURATION_BUCKETS_S: &[f64] = &[
    0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0,
];

/// Default bucket values for WAL write latency (milliseconds).
const WAL_LATENCY_BUCKETS_MS: &[f64] = &[
    0.1, 0.5, 1.0, 2.0, 5.0, 10.0, 25.0, 50.0, 100.0, 250.0, 500.0,
];

/// Default bucket values for network message size (bytes).
const NET_MSG_SIZE_BUCKETS: &[f64] = &[
    64.0, 128.0, 256.0, 512.0, 1024.0, 2048.0, 4096.0,
    8192.0, 16384.0, 32768.0, 65536.0, 131072.0, 262144.0,
];

// -----------------------------------------------------------------------------
// Configuration
// -----------------------------------------------------------------------------

/// Configuration for metrics.
#[derive(Debug, Clone)]
pub struct MetricsConfig {
    /// Enable consensus metrics.
    pub enable_consensus: bool,
    /// Enable mempool metrics.
    pub enable_mempool: bool,
    /// Enable network metrics.
    pub enable_network: bool,
    /// Enable RPC metrics.
    pub enable_rpc: bool,
    /// Enable storage metrics.
    pub enable_storage: bool,
    /// Enable finality metrics.
    pub enable_finality: bool,
    /// Enable protocol metrics.
    pub enable_protocol: bool,
    /// Enable migration metrics.
    pub enable_migration: bool,
    /// Enable rate limiting metrics.
    pub enable_rate_limiting: bool,
    /// Enable snapshot metrics.
    pub enable_snapshots: bool,
    /// Enable audit metrics.
    pub enable_audit: bool,
    /// Enable quantum metrics (coherence, entropy).
    pub enable_quantum: bool,
    /// Enable labeled metrics (high cardinality).
    pub enable_labels: bool,
    /// HTTP server address for metrics endpoint.
    pub listen_address: Option<SocketAddr>,
    /// HTTP server timeout (seconds).
    pub http_timeout_secs: u64,
    /// Enable OpenTelemetry export.
    pub enable_otel: bool,
    /// OpenTelemetry endpoint.
    pub otel_endpoint: Option<String>,
    /// OpenTelemetry service name.
    pub otel_service_name: String,
}

impl Default for MetricsConfig {
    fn default() -> Self {
        Self {
            enable_consensus: true,
            enable_mempool: true,
            enable_network: true,
            enable_rpc: true,
            enable_storage: true,
            enable_finality: true,
            enable_protocol: true,
            enable_migration: true,
            enable_rate_limiting: true,
            enable_snapshots: true,
            enable_audit: true,
            enable_quantum: true,
            enable_labels: false,
            listen_address: None,
            http_timeout_secs: DEFAULT_HTTP_TIMEOUT_SECS,
            enable_otel: false,
            otel_endpoint: None,
            otel_service_name: "iona-node".into(),
        }
    }
}

impl MetricsConfig {
    /// Validate the configuration.
    pub fn validate(&self) -> Result<(), String> {
        if self.http_timeout_secs == 0 {
            return Err("http_timeout_secs must be > 0".into());
        }
        if self.enable_otel {
            if self.otel_endpoint.is_none() || self.otel_endpoint.as_ref().unwrap().is_empty() {
                return Err("otel_endpoint must be set when enable_otel is true".into());
            }
            if self.otel_service_name.is_empty() {
                return Err("otel_service_name must be set".into());
            }
        }
        Ok(())
    }
}

// -----------------------------------------------------------------------------
// Quantum Metrics Errors
// -----------------------------------------------------------------------------

/// Errors that can occur during quantum metrics operations.
#[derive(Debug, Error)]
pub enum MetricsError {
    #[error("failed to register quantum observable '{name}': {source}")]
    Registration {
        name: String,
        #[source]
        source: prometheus::Error,
    },

    #[error("measurement collapse error: {source}")]
    Render {
        #[source]
        source: prometheus::Error,
    },

    #[error("quantum decoherence: registry coherence {coherence} below threshold")]
    Decoherence { coherence: f64 },

    #[error("incompatible observables: cannot measure {a} and {b} simultaneously")]
    IncompatibleObservables { a: String, b: String },

    #[error("metrics server error: {source}")]
    Server {
        #[source]
        source: std::io::Error,
    },

    #[error("configuration error: {0}")]
    Config(String),

    #[error("OpenTelemetry error: {0}")]
    Otel(String),
}

pub type MetricsResult<T> = Result<T, MetricsError>;

// -----------------------------------------------------------------------------
// Quantum Global Registry
// -----------------------------------------------------------------------------

/// Global quantum observable registry.
static REGISTRY: OnceLock<Registry> = OnceLock::new();

/// Get or initialize the global registry.
fn registry() -> &'static Registry {
    REGISTRY.get_or_init(Registry::new)
}

/// Reset the global registry (for testing).
#[cfg(test)]
fn reset_registry() {
    if let Some(r) = REGISTRY.take() {
        drop(r);
    }
    // Re-initialize as empty.
    REGISTRY.set(Registry::new()).ok();
}

// -----------------------------------------------------------------------------
// Metric Creation Helpers (reduce boilerplate)
// -----------------------------------------------------------------------------

fn make_int_counter(registry: &Registry, name: &str, help: &str, enabled: bool) -> MetricsResult<IntCounter> {
    let full_name = format!("{}_{}", METRIC_PREFIX, name);
    let counter = IntCounter::with_opts(Opts::new(&full_name, help))
        .map_err(|e| MetricsError::Registration { name: full_name.clone(), source: e })?;
    if enabled {
        registry.register(Box::new(counter.clone()))
            .map_err(|e| MetricsError::Registration { name: full_name, source: e })?;
    }
    Ok(counter)
}

fn make_int_gauge(registry: &Registry, name: &str, help: &str, enabled: bool) -> MetricsResult<IntGauge> {
    let full_name = format!("{}_{}", METRIC_PREFIX, name);
    let gauge = IntGauge::with_opts(Opts::new(&full_name, help))
        .map_err(|e| MetricsError::Registration { name: full_name.clone(), source: e })?;
    if enabled {
        registry.register(Box::new(gauge.clone()))
            .map_err(|e| MetricsError::Registration { name: full_name, source: e })?;
    }
    Ok(gauge)
}

fn make_gauge(registry: &Registry, name: &str, help: &str, enabled: bool) -> MetricsResult<Gauge> {
    let full_name = format!("{}_{}", METRIC_PREFIX, name);
    let gauge = Gauge::with_opts(Opts::new(&full_name, help))
        .map_err(|e| MetricsError::Registration { name: full_name.clone(), source: e })?;
    if enabled {
        registry.register(Box::new(gauge.clone()))
            .map_err(|e| MetricsError::Registration { name: full_name, source: e })?;
    }
    Ok(gauge)
}

fn make_histogram(registry: &Registry, name: &str, help: &str, buckets: &[f64], enabled: bool) -> MetricsResult<Histogram> {
    let full_name = format!("{}_{}", METRIC_PREFIX, name);
    let histogram = Histogram::with_opts(
        HistogramOpts::new(&full_name, help).buckets(buckets.to_vec()),
    )
    .map_err(|e| MetricsError::Registration { name: full_name.clone(), source: e })?;
    if enabled {
        registry.register(Box::new(histogram.clone()))
            .map_err(|e| MetricsError::Registration { name: full_name, source: e })?;
    }
    Ok(histogram)
}

// -----------------------------------------------------------------------------
// Quantum Metric Handles
// -----------------------------------------------------------------------------

/// Collection of all quantum observables for the IONA node.
#[derive(Debug)]
pub struct Metrics {
    // ── Consensus Observables ──────────────────────────────────────────
    pub blocks_committed: IntCounter,
    pub rounds_advanced: IntCounter,
    pub consensus_height: IntGauge,
    pub block_time_ms: Histogram,

    // ── Throughput Observables ─────────────────────────────────────────
    pub txs_per_block: Histogram,
    pub gas_per_block: Histogram,
    pub base_fee: Gauge,

    // ── Mempool Observables ────────────────────────────────────────────
    pub mempool_size: IntGauge,
    pub mempool_admitted: IntCounter,
    pub mempool_rejected: IntCounter,
    pub mempool_evicted: IntCounter,
    pub mempool_expired: IntCounter,
    pub mempool_rbf: IntCounter,

    // ── Network Observables ────────────────────────────────────────────
    pub p2p_peers: IntGauge,
    pub msgs_broadcast: IntCounter,
    pub msgs_received: IntCounter,
    pub block_requests: IntCounter,
    pub range_syncs: IntCounter,
    pub net_msg_size_bytes: Histogram,
    pub net_latency_ms: Histogram,

    // ── RPC Observables ────────────────────────────────────────────────
    pub rpc_requests: IntCounter,
    pub rpc_tx_submitted: IntCounter,
    pub rpc_errors: IntCounter,
    pub rpc_duration_seconds: Histogram,

    // ── Storage Observables ────────────────────────────────────────────
    pub wal_writes: IntCounter,
    pub wal_write_errors: IntCounter,
    pub state_saves: IntCounter,
    pub wal_latency_ms: Histogram,
    pub storage_size_bytes: Gauge,

    // ── Finality Observables ───────────────────────────────────────────
    pub finality_latency_ms: Histogram,
    pub finality_height: IntGauge,
    pub finality_certificates: IntCounter,

    // ── Protocol Observables ───────────────────────────────────────────
    pub protocol_version: IntGauge,
    pub schema_version: IntGauge,

    // ── Migration Observables ──────────────────────────────────────────
    pub migration_running: IntGauge,
    pub migration_completed: IntCounter,
    pub migration_errors: IntCounter,

    // ── Rate Limiting Observables ──────────────────────────────────────
    pub p2p_rate_limited: IntCounter,
    pub p2p_peers_banned: IntCounter,
    pub p2p_peers_quarantined: IntCounter,
    pub rpc_rate_limited: IntCounter,

    // ── Snapshot Observables ───────────────────────────────────────────
    pub snapshots_created: IntCounter,
    pub snapshots_loaded: IntCounter,
    pub snapshot_size_bytes: Gauge,

    // ── Audit Observables ──────────────────────────────────────────────
    pub audit_events: IntCounter,

    // ── Quantum Observables ────────────────────────────────────────────
    pub node_coherence: Gauge,
    pub entanglement_entropy: Gauge,
    pub measurement_count: IntCounter,

    // ── Labeled metrics (optional) ─────────────────────────────────────
    pub rpc_requests_by_method: Option<prometheus::CounterVec>,
    pub p2p_messages_by_type: Option<prometheus::CounterVec>,
    pub mempool_txs_by_type: Option<prometheus::CounterVec>,

    // ── Internal registry reference ────────────────────────────────────
    registry: &'static Registry,
}

impl Metrics {
    /// Create and register all quantum observables based on config.
    pub fn new(config: &MetricsConfig) -> MetricsResult<Self> {
        let r = registry();

        // Consensus
        let blocks_committed = make_int_counter(r, "blocks_committed_total", "Total blocks committed", config.enable_consensus)?;
        let rounds_advanced = make_int_counter(r, "rounds_advanced_total", "Total BFT rounds advanced", config.enable_consensus)?;
        let consensus_height = make_int_gauge(r, "consensus_height", "Current consensus height", config.enable_consensus)?;
        let block_time_ms = make_histogram(r, "block_time_ms", "Block commit latency in milliseconds", BLOCK_TIME_BUCKETS_MS, config.enable_consensus)?;

        // Throughput
        let txs_per_block = make_histogram(r, "txs_per_block", "Transactions per committed block", TXS_PER_BLOCK_BUCKETS, config.enable_consensus)?;
        let gas_per_block = make_histogram(r, "gas_per_block", "Gas used per committed block", GAS_PER_BLOCK_BUCKETS, config.enable_consensus)?;
        let base_fee = make_gauge(r, "base_fee_per_gas", "Current EIP-1559 base fee per gas", config.enable_consensus)?;

        // Mempool
        let mempool_size = make_int_gauge(r, "mempool_size", "Current mempool transaction count", config.enable_mempool)?;
        let mempool_admitted = make_int_counter(r, "mempool_admitted_total", "Transactions admitted to mempool", config.enable_mempool)?;
        let mempool_rejected = make_int_counter(r, "mempool_rejected_total", "Transactions rejected", config.enable_mempool)?;
        let mempool_evicted = make_int_counter(r, "mempool_evicted_total", "Transactions evicted from mempool", config.enable_mempool)?;
        let mempool_expired = make_int_counter(r, "mempool_expired_total", "Transactions expired by TTL", config.enable_mempool)?;
        let mempool_rbf = make_int_counter(r, "mempool_rbf_total", "Replace-by-fee replacements", config.enable_mempool)?;

        // Network
        let p2p_peers = make_int_gauge(r, "p2p_peers", "Connected P2P peers", config.enable_network)?;
        let msgs_broadcast = make_int_counter(r, "msgs_broadcast_total", "Gossip messages broadcast", config.enable_network)?;
        let msgs_received = make_int_counter(r, "msgs_received_total", "Gossip messages received", config.enable_network)?;
        let block_requests = make_int_counter(r, "block_requests_total", "Block fetch requests sent", config.enable_network)?;
        let range_syncs = make_int_counter(r, "range_syncs_total", "Block range sync operations", config.enable_network)?;
        let net_msg_size_bytes = make_histogram(r, "net_msg_size_bytes", "Network message size in bytes", NET_MSG_SIZE_BUCKETS, config.enable_network)?;
        let net_latency_ms = make_histogram(r, "net_latency_ms", "Network round-trip latency in milliseconds", &[1.0, 5.0, 10.0, 25.0, 50.0, 100.0, 200.0, 500.0, 1000.0], config.enable_network)?;

        // RPC
        let rpc_requests = make_int_counter(r, "rpc_requests_total", "Total RPC requests", config.enable_rpc)?;
        let rpc_tx_submitted = make_int_counter(r, "rpc_tx_submitted_total", "Transactions submitted via RPC", config.enable_rpc)?;
        let rpc_errors = make_int_counter(r, "rpc_errors_total", "RPC errors returned", config.enable_rpc)?;
        let rpc_duration_seconds = make_histogram(r, "rpc_request_duration_seconds", "RPC request duration in seconds", RPC_DURATION_BUCKETS_S, config.enable_rpc)?;

        // Storage
        let wal_writes = make_int_counter(r, "wal_writes_total", "WAL write operations", config.enable_storage)?;
        let wal_write_errors = make_int_counter(r, "wal_write_errors_total", "WAL write errors", config.enable_storage)?;
        let state_saves = make_int_counter(r, "state_saves_total", "State snapshots saved to disk", config.enable_storage)?;
        let wal_latency_ms = make_histogram(r, "wal_latency_ms", "WAL write latency in milliseconds", WAL_LATENCY_BUCKETS_MS, config.enable_storage)?;
        let storage_size_bytes = make_gauge(r, "storage_size_bytes", "Total storage size in bytes", config.enable_storage)?;

        // Finality
        let finality_latency_ms = make_histogram(r, "finality_latency_ms", "Time from proposal to finality in milliseconds", FINALITY_LATENCY_BUCKETS_MS, config.enable_finality)?;
        let finality_height = make_int_gauge(r, "finality_height", "Latest finalized block height", config.enable_finality)?;
        let finality_certificates = make_int_counter(r, "finality_certificates_total", "Finality certificates issued", config.enable_finality)?;

        // Protocol
        let protocol_version = make_int_gauge(r, "protocol_version", "Current active protocol version", config.enable_protocol)?;
        let schema_version = make_int_gauge(r, "schema_version", "Current storage schema version", config.enable_protocol)?;

        // Migration
        let migration_running = make_int_gauge(r, "migration_running", "Number of migrations currently running", config.enable_migration)?;
        let migration_completed = make_int_counter(r, "migrations_completed_total", "Migrations completed successfully", config.enable_migration)?;
        let migration_errors = make_int_counter(r, "migration_errors_total", "Migration errors", config.enable_migration)?;

        // Rate Limiting
        let p2p_rate_limited = make_int_counter(r, "p2p_rate_limited_total", "P2P requests rate-limited", config.enable_rate_limiting)?;
        let p2p_peers_banned = make_int_counter(r, "p2p_peers_banned_total", "Peers permanently banned", config.enable_rate_limiting)?;
        let p2p_peers_quarantined = make_int_counter(r, "p2p_peers_quarantined_total", "Peers quarantined", config.enable_rate_limiting)?;
        let rpc_rate_limited = make_int_counter(r, "rpc_rate_limited_total", "RPC requests rate-limited", config.enable_rate_limiting)?;

        // Snapshots
        let snapshots_created = make_int_counter(r, "snapshots_created_total", "State snapshots created", config.enable_snapshots)?;
        let snapshots_loaded = make_int_counter(r, "snapshots_loaded_total", "State snapshots loaded", config.enable_snapshots)?;
        let snapshot_size_bytes = make_gauge(r, "snapshot_size_bytes", "Size of latest snapshot in bytes", config.enable_snapshots)?;

        // Audit
        let audit_events = make_int_counter(r, "audit_events_total", "Total audit events logged", config.enable_audit)?;

        // Quantum
        let node_coherence = make_gauge(r, "node_coherence", "Node quantum coherence (state purity γ = Tr(ρ²))", config.enable_quantum)?;
        let entanglement_entropy = make_gauge(r, "entanglement_entropy", "Node entanglement entropy S = -Tr(ρ ln ρ)", config.enable_quantum)?;
        let measurement_count = make_int_counter(r, "measurement_count_total", "Total measurement operations (scrape count)", config.enable_quantum)?;

        // Labeled metrics (optional)
        let rpc_requests_by_method = if config.enable_labels && config.enable_rpc {
            let opts = Opts::new(
                &format!("{}_{}", METRIC_PREFIX, "rpc_requests_by_method_total"),
                "RPC requests by method",
            );
            let vec = prometheus::CounterVec::new(opts, &["method"])
                .map_err(|e| MetricsError::Registration { name: "rpc_requests_by_method".into(), source: e })?;
            r.register(Box::new(vec.clone()))
                .map_err(|e| MetricsError::Registration { name: "rpc_requests_by_method".into(), source: e })?;
            Some(vec)
        } else {
            None
        };

        let p2p_messages_by_type = if config.enable_labels && config.enable_network {
            let opts = Opts::new(
                &format!("{}_{}", METRIC_PREFIX, "p2p_messages_by_type_total"),
                "P2P messages by type",
            );
            let vec = prometheus::CounterVec::new(opts, &["type"])
                .map_err(|e| MetricsError::Registration { name: "p2p_messages_by_type".into(), source: e })?;
            r.register(Box::new(vec.clone()))
                .map_err(|e| MetricsError::Registration { name: "p2p_messages_by_type".into(), source: e })?;
            Some(vec)
        } else {
            None
        };

        let mempool_txs_by_type = if config.enable_labels && config.enable_mempool {
            let opts = Opts::new(
                &format!("{}_{}", METRIC_PREFIX, "mempool_txs_by_type_total"),
                "Mempool transactions by type",
            );
            let vec = prometheus::CounterVec::new(opts, &["type"])
                .map_err(|e| MetricsError::Registration { name: "mempool_txs_by_type".into(), source: e })?;
            r.register(Box::new(vec.clone()))
                .map_err(|e| MetricsError::Registration { name: "mempool_txs_by_type".into(), source: e })?;
            Some(vec)
        } else {
            None
        };

        Ok(Self {
            blocks_committed,
            rounds_advanced,
            consensus_height,
            block_time_ms,
            txs_per_block,
            gas_per_block,
            base_fee,
            mempool_size,
            mempool_admitted,
            mempool_rejected,
            mempool_evicted,
            mempool_expired,
            mempool_rbf,
            p2p_peers,
            msgs_broadcast,
            msgs_received,
            block_requests,
            range_syncs,
            net_msg_size_bytes,
            net_latency_ms,
            rpc_requests,
            rpc_tx_submitted,
            rpc_errors,
            rpc_duration_seconds,
            wal_writes,
            wal_write_errors,
            state_saves,
            wal_latency_ms,
            storage_size_bytes,
            finality_latency_ms,
            finality_height,
            finality_certificates,
            protocol_version,
            schema_version,
            migration_running,
            migration_completed,
            migration_errors,
            p2p_rate_limited,
            p2p_peers_banned,
            p2p_peers_quarantined,
            rpc_rate_limited,
            snapshots_created,
            snapshots_loaded,
            snapshot_size_bytes,
            audit_events,
            node_coherence,
            entanglement_entropy,
            measurement_count,
            rpc_requests_by_method,
            p2p_messages_by_type,
            mempool_txs_by_type,
            registry: r,
        })
    }

    /// Apply quantum decoherence to the metrics registry (placeholder).
    /// In practice, this could adjust gauge values to reflect measurement disturbance.
    pub fn apply_decoherence(&self) {
        self.node_coherence.set(0.99);
        self.entanglement_entropy.set(0.01);
    }

    /// Increment measurement count.
    pub fn record_measurement(&self) {
        self.measurement_count.inc();
        self.apply_decoherence();
    }
}

// -----------------------------------------------------------------------------
// Quantum Rendering
// -----------------------------------------------------------------------------

/// Render all registered quantum observables as Prometheus text format.
pub fn render() -> String {
    if let Some(metrics) = get_metrics() {
        metrics.record_measurement();
    }

    let encoder = TextEncoder::new();
    let metric_families = registry().gather();
    let mut buffer = Vec::new();

    if let Err(e) = encoder.encode(&metric_families, &mut buffer) {
        warn!("failed to encode quantum observables: {}", e);
        return String::new();
    }

    String::from_utf8(buffer).unwrap_or_else(|e| {
        warn!("quantum measurement output is not valid UTF-8: {}", e);
        String::new()
    })
}

/// Render metrics with quantum metadata header.
pub fn render_with_metadata() -> String {
    let metrics = render();
    let metadata = format!(
        "# HELP iona_measurement_epoch_seconds Time of last measurement in seconds since epoch\n\
         # TYPE iona_measurement_epoch_seconds gauge\n\
         iona_measurement_epoch_seconds {}\n",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
    );
    format!("{metadata}{metrics}")
}

// -----------------------------------------------------------------------------
// HTTP Server
// -----------------------------------------------------------------------------

/// Start the metrics HTTP server.
pub async fn serve_metrics(
    addr: SocketAddr,
    config: &MetricsConfig,
    shutdown_rx: tokio::sync::watch::Receiver<()>,
) -> Result<(), MetricsError> {
    use axum::{
        extract::State,
        response::IntoResponse,
        routing::get,
        Router,
    };
    use std::sync::Arc;

    let timeout = Duration::from_secs(config.http_timeout_secs);

    // Ensure metrics are initialized.
    let _ = init_metrics(config)?;

    let app = Router::new()
        .route("/metrics", get(metrics_handler))
        .with_state(Arc::new(timeout));

    info!("Metrics server listening on {}", addr);

    axum::Server::bind(&addr)
        .serve(app.into_make_service())
        .with_graceful_shutdown(async {
            let mut rx = shutdown_rx;
            let _ = rx.changed().await;
            info!("Metrics server shutting down");
        })
        .await
        .map_err(|e| MetricsError::Server { source: e })?;

    Ok(())
}

async fn metrics_handler(State(timeout): State<Arc<Duration>>) -> impl IntoResponse {
    // Simulate decoherence during measurement.
    tokio::time::sleep(Duration::from_millis(10)).await;

    let content = render_with_metadata();
    (
        axum::http::StatusCode::OK,
        [(
            axum::http::header::CONTENT_TYPE,
            "text/plain; version=0.0.4; charset=utf-8",
        )],
        content,
    )
}

// -----------------------------------------------------------------------------
// Global Metric Access
// -----------------------------------------------------------------------------

static METRICS: OnceLock<Metrics> = OnceLock::new();

/// Initialize global metrics.
pub fn init_metrics(config: &MetricsConfig) -> MetricsResult<&'static Metrics> {
    if let Some(m) = METRICS.get() {
        return Ok(m);
    }
    let metrics = Metrics::new(config)?;
    METRICS
        .set(metrics)
        .map_err(|_| MetricsError::Registration {
            name: "global_metrics".into(),
            source: prometheus::Error::Msg("already initialized".into()),
        })?;
    Ok(METRICS.get().unwrap())
}

/// Get the global metrics instance.
pub fn metrics() -> Option<&'static Metrics> {
    METRICS.get()
}

/// Get the global metrics instance (internal use).
fn get_metrics() -> Option<&'static Metrics> {
    METRICS.get()
}

/// Reset global metrics (for testing).
#[cfg(test)]
pub fn reset_metrics() {
    if let Some(m) = METRICS.take() {
        drop(m);
    }
    reset_registry();
}

// -----------------------------------------------------------------------------
// OpenTelemetry Integration (feature‑gated)
// -----------------------------------------------------------------------------

#[cfg(feature = "otel")]
pub fn build_otel_layer(
    config: &MetricsConfig,
) -> MetricsResult<tracing_opentelemetry::OpenTelemetryLayer<
    tracing_subscriber::Registry,
    opentelemetry_sdk::trace::Tracer,
>> {
    if !config.enable_otel {
        return Err(MetricsError::Config("OTEL not enabled".into()));
    }
    let endpoint = config.otel_endpoint.as_ref().ok_or_else(|| {
        MetricsError::Config("OTEL endpoint not set".into())
    })?;
    let service_name = &config.otel_service_name;

    use opentelemetry::trace::TracerProvider as _;
    use opentelemetry::KeyValue;
    use opentelemetry_otlp::WithExportConfig;

    let exporter = opentelemetry_otlp::new_exporter()
        .tonic()
        .with_endpoint(endpoint);

    let provider = opentelemetry_otlp::new_pipeline()
        .tracing()
        .with_exporter(exporter)
        .with_trace_config(
            opentelemetry_sdk::trace::config()
                .with_resource(opentelemetry_sdk::Resource::new(vec![
                    KeyValue::new("service.name", service_name.to_string()),
                ])),
        )
        .install_batch(opentelemetry_sdk::runtime::Tokio)
        .map_err(|e| MetricsError::Otel(e.to_string()))?;

    let tracer = provider.tracer(service_name.to_string());
    Ok(tracing_opentelemetry::layer().with_tracer(tracer))
}

#[cfg(not(feature = "otel"))]
pub fn build_otel_layer(_config: &MetricsConfig) -> MetricsResult<()> {
    Err(MetricsError::Config("OTEL feature not enabled".into()))
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::SocketAddr;
    use std::str::FromStr;

    fn test_config() -> MetricsConfig {
        let mut cfg = MetricsConfig::default();
        cfg.enable_consensus = true;
        cfg.enable_mempool = true;
        cfg.enable_network = true;
        cfg.enable_rpc = true;
        cfg.enable_storage = true;
        cfg.enable_finality = true;
        cfg.enable_protocol = true;
        cfg.enable_migration = true;
        cfg.enable_rate_limiting = true;
        cfg.enable_snapshots = true;
        cfg.enable_audit = true;
        cfg.enable_quantum = true;
        cfg.enable_labels = true;
        cfg
    }

    #[test]
    fn test_config_validation() {
        let cfg = test_config();
        assert!(cfg.validate().is_ok());

        let mut bad = cfg.clone();
        bad.http_timeout_secs = 0;
        assert!(bad.validate().is_err());

        let mut bad2 = cfg.clone();
        bad2.enable_otel = true;
        bad2.otel_endpoint = None;
        assert!(bad2.validate().is_err());
    }

    #[test]
    fn test_metrics_creation() {
        let cfg = test_config();
        let m = Metrics::new(&cfg);
        assert!(m.is_ok());
    }

    #[test]
    fn test_render() {
        let cfg = test_config();
        let _ = Metrics::new(&cfg).unwrap();
        let output = render();
        assert!(output.contains("iona_"));
    }

    #[test]
    fn test_render_with_metadata() {
        let cfg = test_config();
        let _ = Metrics::new(&cfg).unwrap();
        let output = render_with_metadata();
        assert!(output.contains("measurement_epoch_seconds"));
    }

    #[test]
    fn test_int_counter_increment() {
        let cfg = test_config();
        let m = Metrics::new(&cfg).unwrap();
        m.blocks_committed.inc();
        assert_eq!(m.blocks_committed.get(), 1);
        m.blocks_committed.inc_by(5);
        assert_eq!(m.blocks_committed.get(), 6);
    }

    #[test]
    fn test_int_gauge_set() {
        let cfg = test_config();
        let m = Metrics::new(&cfg).unwrap();
        m.consensus_height.set(42);
        assert_eq!(m.consensus_height.get(), 42);
    }

    #[test]
    fn test_gauge_set() {
        let cfg = test_config();
        let m = Metrics::new(&cfg).unwrap();
        m.base_fee.set(100.0);
        assert!((m.base_fee.get() - 100.0).abs() < 1e-10);
    }

    #[test]
    fn test_labeled_metrics() {
        let cfg = test_config();
        let m = Metrics::new(&cfg).unwrap();
        if let Some(ref vec) = m.rpc_requests_by_method {
            vec.with_label_values(&["eth_sendTransaction"]).inc();
            assert_eq!(
                vec.with_label_values(&["eth_sendTransaction"]).get(),
                1
            );
        }
    }

    #[test]
    fn test_measurement_count() {
        let cfg = test_config();
        let m = Metrics::new(&cfg).unwrap();
        render();
        render();
        assert_eq!(m.measurement_count.get(), 2);
    }

    #[test]
    fn test_global_metrics() {
        reset_metrics();
        let cfg = test_config();
        let _ = init_metrics(&cfg).unwrap();
        let m = metrics().unwrap();
        m.blocks_committed.inc_by(10);
        assert_eq!(m.blocks_committed.get(), 10);
    }

    #[test]
    fn test_conditional_metrics() {
        let mut cfg = test_config();
        cfg.enable_consensus = false;
        let m = Metrics::new(&cfg).unwrap();
        // Should still exist but not increment.
        m.blocks_committed.inc_by(5);
        assert_eq!(m.blocks_committed.get(), 5); // It still increments because it's created.
    }

    #[test]
    fn test_otel_layer_feature_gated() {
        #[cfg(feature = "otel")]
        {
            let cfg = test_config();
            let result = build_otel_layer(&cfg);
            assert!(result.is_err());
        }
        #[cfg(not(feature = "otel"))]
        {
            let cfg = test_config();
            let result = build_otel_layer(&cfg);
            assert!(result.is_err());
        }
    }

    #[test]
    fn test_decoherence_application() {
        let cfg = test_config();
        let m = Metrics::new(&cfg).unwrap();
        m.apply_decoherence();
        assert!((m.node_coherence.get() - 0.99).abs() < 1e-10);
        assert!((m.entanglement_entropy.get() - 0.01).abs() < 1e-10);
    }
}
