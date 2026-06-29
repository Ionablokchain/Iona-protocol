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

        // Helper macros for metric creation with error propagation
        macro_rules! int_counter {
            ($name:expr, $help:expr) => {{
                let full_name = format!("{}_{}", METRIC_PREFIX, $name);
                let c = IntCounter::with_opts(Opts::new(&full_name, $help))
                    .map_err(|e| MetricsError::Registration {
                        name: full_name.clone(),
                        source: e,
                    })?;
                r.register(Box::new(c.clone()))
                    .map_err(|e| MetricsError::Registration {
                        name: full_name,
                        source: e,
                    })?;
                c
            }};
        }

        macro_rules! int_gauge {
            ($name:expr, $help:expr) => {{
                let full_name = format!("{}_{}", METRIC_PREFIX, $name);
                let g = IntGauge::with_opts(Opts::new(&full_name, $help))
                    .map_err(|e| MetricsError::Registration {
                        name: full_name.clone(),
                        source: e,
                    })?;
                r.register(Box::new(g.clone()))
                    .map_err(|e| MetricsError::Registration {
                        name: full_name,
                        source: e,
                    })?;
                g
            }};
        }

        macro_rules! gauge {
            ($name:expr, $help:expr) => {{
                let full_name = format!("{}_{}", METRIC_PREFIX, $name);
                let g = Gauge::with_opts(Opts::new(&full_name, $help))
                    .map_err(|e| MetricsError::Registration {
                        name: full_name.clone(),
                        source: e,
                    })?;
                r.register(Box::new(g.clone()))
                    .map_err(|e| MetricsError::Registration {
                        name: full_name,
                        source: e,
                    })?;
                g
            }};
        }

        macro_rules! histogram {
            ($name:expr, $help:expr, $buckets:expr) => {{
                let full_name = format!("{}_{}", METRIC_PREFIX, $name);
                let h = Histogram::with_opts(
                    HistogramOpts::new(&full_name, $help).buckets($buckets.to_vec()),
                )
                .map_err(|e| MetricsError::Registration {
                    name: full_name.clone(),
                    source: e,
                })?;
                r.register(Box::new(h.clone()))
                    .map_err(|e| MetricsError::Registration {
                        name: full_name,
                        source: e,
                    })?;
                h
            }};
        }

        // Create all metrics conditionally.
        let blocks_committed = if config.enable_consensus {
            int_counter!("blocks_committed_total", "Total blocks committed")
        } else {
            // Register a dummy metric that never increments.
            let c = IntCounter::with_opts(Opts::new(
                &format!("{}_{}", METRIC_PREFIX, "blocks_committed_total"),
                "Total blocks committed",
            )).unwrap();
            r.register(Box::new(c.clone())).ok();
            c
        };

        let rounds_advanced = if config.enable_consensus {
            int_counter!("rounds_advanced_total", "Total BFT rounds advanced")
        } else {
            let c = IntCounter::with_opts(Opts::new(
                &format!("{}_{}", METRIC_PREFIX, "rounds_advanced_total"),
                "Total BFT rounds advanced",
            )).unwrap();
            r.register(Box::new(c.clone())).ok();
            c
        };

        let consensus_height = if config.enable_consensus {
            int_gauge!("consensus_height", "Current consensus height")
        } else {
            let g = IntGauge::with_opts(Opts::new(
                &format!("{}_{}", METRIC_PREFIX, "consensus_height"),
                "Current consensus height",
            )).unwrap();
            r.register(Box::new(g.clone())).ok();
            g
        };

        let block_time_ms = if config.enable_consensus {
            histogram!("block_time_ms", "Block commit latency in milliseconds", BLOCK_TIME_BUCKETS_MS)
        } else {
            let h = Histogram::with_opts(
                HistogramOpts::new(
                    &format!("{}_{}", METRIC_PREFIX, "block_time_ms"),
                    "Block commit latency in milliseconds",
                ).buckets(BLOCK_TIME_BUCKETS_MS.to_vec()),
            ).unwrap();
            r.register(Box::new(h.clone())).ok();
            h
        };

        // Throughput
        let txs_per_block = if config.enable_consensus {
            histogram!("txs_per_block", "Transactions per committed block", TXS_PER_BLOCK_BUCKETS)
        } else {
            let h = Histogram::with_opts(
                HistogramOpts::new(
                    &format!("{}_{}", METRIC_PREFIX, "txs_per_block"),
                    "Transactions per committed block",
                ).buckets(TXS_PER_BLOCK_BUCKETS.to_vec()),
            ).unwrap();
            r.register(Box::new(h.clone())).ok();
            h
        };

        let gas_per_block = if config.enable_consensus {
            histogram!("gas_per_block", "Gas used per committed block", GAS_PER_BLOCK_BUCKETS)
        } else {
            let h = Histogram::with_opts(
                HistogramOpts::new(
                    &format!("{}_{}", METRIC_PREFIX, "gas_per_block"),
                    "Gas used per committed block",
                ).buckets(GAS_PER_BLOCK_BUCKETS.to_vec()),
            ).unwrap();
            r.register(Box::new(h.clone())).ok();
            h
        };

        let base_fee = if config.enable_consensus {
            gauge!("base_fee_per_gas", "Current EIP-1559 base fee per gas")
        } else {
            let g = Gauge::with_opts(Opts::new(
                &format!("{}_{}", METRIC_PREFIX, "base_fee_per_gas"),
                "Current EIP-1559 base fee per gas",
            )).unwrap();
            r.register(Box::new(g.clone())).ok();
            g
        };

        // Mempool
        let mempool_size = if config.enable_mempool {
            int_gauge!("mempool_size", "Current mempool transaction count")
        } else {
            let g = IntGauge::with_opts(Opts::new(
                &format!("{}_{}", METRIC_PREFIX, "mempool_size"),
                "Current mempool transaction count",
            )).unwrap();
            r.register(Box::new(g.clone())).ok();
            g
        };

        let mempool_admitted = if config.enable_mempool {
            int_counter!("mempool_admitted_total", "Transactions admitted to mempool")
        } else {
            let c = IntCounter::with_opts(Opts::new(
                &format!("{}_{}", METRIC_PREFIX, "mempool_admitted_total"),
                "Transactions admitted to mempool",
            )).unwrap();
            r.register(Box::new(c.clone())).ok();
            c
        };

        let mempool_rejected = if config.enable_mempool {
            int_counter!("mempool_rejected_total", "Transactions rejected")
        } else {
            let c = IntCounter::with_opts(Opts::new(
                &format!("{}_{}", METRIC_PREFIX, "mempool_rejected_total"),
                "Transactions rejected",
            )).unwrap();
            r.register(Box::new(c.clone())).ok();
            c
        };

        let mempool_evicted = if config.enable_mempool {
            int_counter!("mempool_evicted_total", "Transactions evicted from mempool")
        } else {
            let c = IntCounter::with_opts(Opts::new(
                &format!("{}_{}", METRIC_PREFIX, "mempool_evicted_total"),
                "Transactions evicted from mempool",
            )).unwrap();
            r.register(Box::new(c.clone())).ok();
            c
        };

        let mempool_expired = if config.enable_mempool {
            int_counter!("mempool_expired_total", "Transactions expired by TTL")
        } else {
            let c = IntCounter::with_opts(Opts::new(
                &format!("{}_{}", METRIC_PREFIX, "mempool_expired_total"),
                "Transactions expired by TTL",
            )).unwrap();
            r.register(Box::new(c.clone())).ok();
            c
        };

        let mempool_rbf = if config.enable_mempool {
            int_counter!("mempool_rbf_total", "Replace-by-fee replacements")
        } else {
            let c = IntCounter::with_opts(Opts::new(
                &format!("{}_{}", METRIC_PREFIX, "mempool_rbf_total"),
                "Replace-by-fee replacements",
            )).unwrap();
            r.register(Box::new(c.clone())).ok();
            c
        };

        // Network
        let p2p_peers = if config.enable_network {
            int_gauge!("p2p_peers", "Connected P2P peers")
        } else {
            let g = IntGauge::with_opts(Opts::new(
                &format!("{}_{}", METRIC_PREFIX, "p2p_peers"),
                "Connected P2P peers",
            )).unwrap();
            r.register(Box::new(g.clone())).ok();
            g
        };

        let msgs_broadcast = if config.enable_network {
            int_counter!("msgs_broadcast_total", "Gossip messages broadcast")
        } else {
            let c = IntCounter::with_opts(Opts::new(
                &format!("{}_{}", METRIC_PREFIX, "msgs_broadcast_total"),
                "Gossip messages broadcast",
            )).unwrap();
            r.register(Box::new(c.clone())).ok();
            c
        };

        let msgs_received = if config.enable_network {
            int_counter!("msgs_received_total", "Gossip messages received")
        } else {
            let c = IntCounter::with_opts(Opts::new(
                &format!("{}_{}", METRIC_PREFIX, "msgs_received_total"),
                "Gossip messages received",
            )).unwrap();
            r.register(Box::new(c.clone())).ok();
            c
        };

        let block_requests = if config.enable_network {
            int_counter!("block_requests_total", "Block fetch requests sent")
        } else {
            let c = IntCounter::with_opts(Opts::new(
                &format!("{}_{}", METRIC_PREFIX, "block_requests_total"),
                "Block fetch requests sent",
            )).unwrap();
            r.register(Box::new(c.clone())).ok();
            c
        };

        let range_syncs = if config.enable_network {
            int_counter!("range_syncs_total", "Block range sync operations")
        } else {
            let c = IntCounter::with_opts(Opts::new(
                &format!("{}_{}", METRIC_PREFIX, "range_syncs_total"),
                "Block range sync operations",
            )).unwrap();
            r.register(Box::new(c.clone())).ok();
            c
        };

        let net_msg_size_bytes = if config.enable_network {
            histogram!("net_msg_size_bytes", "Network message size in bytes", NET_MSG_SIZE_BUCKETS)
        } else {
            let h = Histogram::with_opts(
                HistogramOpts::new(
                    &format!("{}_{}", METRIC_PREFIX, "net_msg_size_bytes"),
                    "Network message size in bytes",
                ).buckets(NET_MSG_SIZE_BUCKETS.to_vec()),
            ).unwrap();
            r.register(Box::new(h.clone())).ok();
            h
        };

        let net_latency_ms = if config.enable_network {
            histogram!("net_latency_ms", "Network round-trip latency in milliseconds", &[1.0, 5.0, 10.0, 25.0, 50.0, 100.0, 200.0, 500.0, 1000.0])
        } else {
            let h = Histogram::with_opts(
                HistogramOpts::new(
                    &format!("{}_{}", METRIC_PREFIX, "net_latency_ms"),
                    "Network round-trip latency in milliseconds",
                ).buckets(vec![1.0, 5.0, 10.0, 25.0, 50.0, 100.0, 200.0, 500.0, 1000.0]),
            ).unwrap();
            r.register(Box::new(h.clone())).ok();
            h
        };

        // RPC
        let rpc_requests = if config.enable_rpc {
            int_counter!("rpc_requests_total", "Total RPC requests")
        } else {
            let c = IntCounter::with_opts(Opts::new(
                &format!("{}_{}", METRIC_PREFIX, "rpc_requests_total"),
                "Total RPC requests",
            )).unwrap();
            r.register(Box::new(c.clone())).ok();
            c
        };

        let rpc_tx_submitted = if config.enable_rpc {
            int_counter!("rpc_tx_submitted_total", "Transactions submitted via RPC")
        } else {
            let c = IntCounter::with_opts(Opts::new(
                &format!("{}_{}", METRIC_PREFIX, "rpc_tx_submitted_total"),
                "Transactions submitted via RPC",
            )).unwrap();
            r.register(Box::new(c.clone())).ok();
            c
        };

        let rpc_errors = if config.enable_rpc {
            int_counter!("rpc_errors_total", "RPC errors returned")
        } else {
            let c = IntCounter::with_opts(Opts::new(
                &format!("{}_{}", METRIC_PREFIX, "rpc_errors_total"),
                "RPC errors returned",
            )).unwrap();
            r.register(Box::new(c.clone())).ok();
            c
        };

        let rpc_duration_seconds = if config.enable_rpc {
            histogram!("rpc_request_duration_seconds", "RPC request duration in seconds", RPC_DURATION_BUCKETS_S)
        } else {
            let h = Histogram::with_opts(
                HistogramOpts::new(
                    &format!("{}_{}", METRIC_PREFIX, "rpc_request_duration_seconds"),
                    "RPC request duration in seconds",
                ).buckets(RPC_DURATION_BUCKETS_S.to_vec()),
            ).unwrap();
            r.register(Box::new(h.clone())).ok();
            h
        };

        // Storage
        let wal_writes = if config.enable_storage {
            int_counter!("wal_writes_total", "WAL write operations")
        } else {
            let c = IntCounter::with_opts(Opts::new(
                &format!("{}_{}", METRIC_PREFIX, "wal_writes_total"),
                "WAL write operations",
            )).unwrap();
            r.register(Box::new(c.clone())).ok();
            c
        };

        let wal_write_errors = if config.enable_storage {
            int_counter!("wal_write_errors_total", "WAL write errors")
        } else {
            let c = IntCounter::with_opts(Opts::new(
                &format!("{}_{}", METRIC_PREFIX, "wal_write_errors_total"),
                "WAL write errors",
            )).unwrap();
            r.register(Box::new(c.clone())).ok();
            c
        };

        let state_saves = if config.enable_storage {
            int_counter!("state_saves_total", "State snapshots saved to disk")
        } else {
            let c = IntCounter::with_opts(Opts::new(
                &format!("{}_{}", METRIC_PREFIX, "state_saves_total"),
                "State snapshots saved to disk",
            )).unwrap();
            r.register(Box::new(c.clone())).ok();
            c
        };

        let wal_latency_ms = if config.enable_storage {
            histogram!("wal_latency_ms", "WAL write latency in milliseconds", WAL_LATENCY_BUCKETS_MS)
        } else {
            let h = Histogram::with_opts(
                HistogramOpts::new(
                    &format!("{}_{}", METRIC_PREFIX, "wal_latency_ms"),
                    "WAL write latency in milliseconds",
                ).buckets(WAL_LATENCY_BUCKETS_MS.to_vec()),
            ).unwrap();
            r.register(Box::new(h.clone())).ok();
            h
        };

        let storage_size_bytes = if config.enable_storage {
            gauge!("storage_size_bytes", "Total storage size in bytes")
        } else {
            let g = Gauge::with_opts(Opts::new(
                &format!("{}_{}", METRIC_PREFIX, "storage_size_bytes"),
                "Total storage size in bytes",
            )).unwrap();
            r.register(Box::new(g.clone())).ok();
            g
        };

        // Finality
        let finality_latency_ms = if config.enable_finality {
            histogram!("finality_latency_ms", "Time from proposal to finality in milliseconds", FINALITY_LATENCY_BUCKETS_MS)
        } else {
            let h = Histogram::with_opts(
                HistogramOpts::new(
                    &format!("{}_{}", METRIC_PREFIX, "finality_latency_ms"),
                    "Time from proposal to finality in milliseconds",
                ).buckets(FINALITY_LATENCY_BUCKETS_MS.to_vec()),
            ).unwrap();
            r.register(Box::new(h.clone())).ok();
            h
        };

        let finality_height = if config.enable_finality {
            int_gauge!("finality_height", "Latest finalized block height")
        } else {
            let g = IntGauge::with_opts(Opts::new(
                &format!("{}_{}", METRIC_PREFIX, "finality_height"),
                "Latest finalized block height",
            )).unwrap();
            r.register(Box::new(g.clone())).ok();
            g
        };

        let finality_certificates = if config.enable_finality {
            int_counter!("finality_certificates_total", "Finality certificates issued")
        } else {
            let c = IntCounter::with_opts(Opts::new(
                &format!("{}_{}", METRIC_PREFIX, "finality_certificates_total"),
                "Finality certificates issued",
            )).unwrap();
            r.register(Box::new(c.clone())).ok();
            c
        };

        // Protocol
        let protocol_version = if config.enable_protocol {
            int_gauge!("protocol_version", "Current active protocol version")
        } else {
            let g = IntGauge::with_opts(Opts::new(
                &format!("{}_{}", METRIC_PREFIX, "protocol_version"),
                "Current active protocol version",
            )).unwrap();
            r.register(Box::new(g.clone())).ok();
            g
        };

        let schema_version = if config.enable_protocol {
            int_gauge!("schema_version", "Current storage schema version")
        } else {
            let g = IntGauge::with_opts(Opts::new(
                &format!("{}_{}", METRIC_PREFIX, "schema_version"),
                "Current storage schema version",
            )).unwrap();
            r.register(Box::new(g.clone())).ok();
            g
        };

        // Migration
        let migration_running = if config.enable_migration {
            int_gauge!("migration_running", "Number of migrations currently running")
        } else {
            let g = IntGauge::with_opts(Opts::new(
                &format!("{}_{}", METRIC_PREFIX, "migration_running"),
                "Number of migrations currently running",
            )).unwrap();
            r.register(Box::new(g.clone())).ok();
            g
        };

        let migration_completed = if config.enable_migration {
            int_counter!("migrations_completed_total", "Migrations completed successfully")
        } else {
            let c = IntCounter::with_opts(Opts::new(
                &format!("{}_{}", METRIC_PREFIX, "migrations_completed_total"),
                "Migrations completed successfully",
            )).unwrap();
            r.register(Box::new(c.clone())).ok();
            c
        };

        let migration_errors = if config.enable_migration {
            int_counter!("migration_errors_total", "Migration errors")
        } else {
            let c = IntCounter::with_opts(Opts::new(
                &format!("{}_{}", METRIC_PREFIX, "migration_errors_total"),
                "Migration errors",
            )).unwrap();
            r.register(Box::new(c.clone())).ok();
            c
        };

        // Rate Limiting
        let p2p_rate_limited = if config.enable_rate_limiting {
            int_counter!("p2p_rate_limited_total", "P2P requests rate-limited")
        } else {
            let c = IntCounter::with_opts(Opts::new(
                &format!("{}_{}", METRIC_PREFIX, "p2p_rate_limited_total"),
                "P2P requests rate-limited",
            )).unwrap();
            r.register(Box::new(c.clone())).ok();
            c
        };

        let p2p_peers_banned = if config.enable_rate_limiting {
            int_counter!("p2p_peers_banned_total", "Peers permanently banned")
        } else {
            let c = IntCounter::with_opts(Opts::new(
                &format!("{}_{}", METRIC_PREFIX, "p2p_peers_banned_total"),
                "Peers permanently banned",
            )).unwrap();
            r.register(Box::new(c.clone())).ok();
            c
        };

        let p2p_peers_quarantined = if config.enable_rate_limiting {
            int_counter!("p2p_peers_quarantined_total", "Peers quarantined")
        } else {
            let c = IntCounter::with_opts(Opts::new(
                &format!("{}_{}", METRIC_PREFIX, "p2p_peers_quarantined_total"),
                "Peers quarantined",
            )).unwrap();
            r.register(Box::new(c.clone())).ok();
            c
        };

        let rpc_rate_limited = if config.enable_rate_limiting {
            int_counter!("rpc_rate_limited_total", "RPC requests rate-limited")
        } else {
            let c = IntCounter::with_opts(Opts::new(
                &format!("{}_{}", METRIC_PREFIX, "rpc_rate_limited_total"),
                "RPC requests rate-limited",
            )).unwrap();
            r.register(Box::new(c.clone())).ok();
            c
        };

        // Snapshots
        let snapshots_created = if config.enable_snapshots {
            int_counter!("snapshots_created_total", "State snapshots created")
        } else {
            let c = IntCounter::with_opts(Opts::new(
                &format!("{}_{}", METRIC_PREFIX, "snapshots_created_total"),
                "State snapshots created",
            )).unwrap();
            r.register(Box::new(c.clone())).ok();
            c
        };

        let snapshots_loaded = if config.enable_snapshots {
            int_counter!("snapshots_loaded_total", "State snapshots loaded")
        } else {
            let c = IntCounter::with_opts(Opts::new(
                &format!("{}_{}", METRIC_PREFIX, "snapshots_loaded_total"),
                "State snapshots loaded",
            )).unwrap();
            r.register(Box::new(c.clone())).ok();
            c
        };

        let snapshot_size_bytes = if config.enable_snapshots {
            gauge!("snapshot_size_bytes", "Size of latest snapshot in bytes")
        } else {
            let g = Gauge::with_opts(Opts::new(
                &format!("{}_{}", METRIC_PREFIX, "snapshot_size_bytes"),
                "Size of latest snapshot in bytes",
            )).unwrap();
            r.register(Box::new(g.clone())).ok();
            g
        };

        // Audit
        let audit_events = if config.enable_audit {
            int_counter!("audit_events_total", "Total audit events logged")
        } else {
            let c = IntCounter::with_opts(Opts::new(
                &format!("{}_{}", METRIC_PREFIX, "audit_events_total"),
                "Total audit events logged",
            )).unwrap();
            r.register(Box::new(c.clone())).ok();
            c
        };

        // Quantum
        let node_coherence = if config.enable_quantum {
            gauge!("node_coherence", "Node quantum coherence (state purity γ = Tr(ρ²))")
        } else {
            let g = Gauge::with_opts(Opts::new(
                &format!("{}_{}", METRIC_PREFIX, "node_coherence"),
                "Node quantum coherence (state purity γ = Tr(ρ²))",
            )).unwrap();
            r.register(Box::new(g.clone())).ok();
            g
        };

        let entanglement_entropy = if config.enable_quantum {
            gauge!("entanglement_entropy", "Node entanglement entropy S = -Tr(ρ ln ρ)")
        } else {
            let g = Gauge::with_opts(Opts::new(
                &format!("{}_{}", METRIC_PREFIX, "entanglement_entropy"),
                "Node entanglement entropy S = -Tr(ρ ln ρ)",
            )).unwrap();
            r.register(Box::new(g.clone())).ok();
            g
        };

        let measurement_count = if config.enable_quantum {
            int_counter!("measurement_count_total", "Total measurement operations (scrape count)")
        } else {
            let c = IntCounter::with_opts(Opts::new(
                &format!("{}_{}", METRIC_PREFIX, "measurement_count_total"),
                "Total measurement operations (scrape count)",
            )).unwrap();
            r.register(Box::new(c.clone())).ok();
            c
        };

        // Labeled metrics (optional)
        let rpc_requests_by_method = if config.enable_labels && config.enable_rpc {
            let opts = Opts::new(
                &format!("{}_{}", METRIC_PREFIX, "rpc_requests_by_method_total"),
                "RPC requests by method",
            );
            let vec = prometheus::CounterVec::new(opts, &["method"])
                .map_err(|e| MetricsError::Registration {
                    name: "rpc_requests_by_method".into(),
                    source: e,
                })?;
            r.register(Box::new(vec.clone()))
                .map_err(|e| MetricsError::Registration {
                    name: "rpc_requests_by_method".into(),
                    source: e,
                })?;
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
                .map_err(|e| MetricsError::Registration {
                    name: "p2p_messages_by_type".into(),
                    source: e,
                })?;
            r.register(Box::new(vec.clone()))
                .map_err(|e| MetricsError::Registration {
                    name: "p2p_messages_by_type".into(),
                    source: e,
                })?;
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
                .map_err(|e| MetricsError::Registration {
                    name: "mempool_txs_by_type".into(),
                    source: e,
                })?;
            r.register(Box::new(vec.clone()))
                .map_err(|e| MetricsError::Registration {
                    name: "mempool_txs_by_type".into(),
                    source: e,
                })?;
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
        // Update the node_coherence and entanglement_entropy gauges
        // based on some internal model, if enabled.
        // For now, we just set a default value.
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
    // Drop the current metrics.
    if let Some(m) = METRICS.take() {
        drop(m);
    }
    // Reset registry.
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
        // No error, but metric may be unused.
        assert_eq!(m.blocks_committed.get(), 5); // It still increments because it's registered.
        // The metric is registered as dummy but we can still increment it.
        // That's okay; in practice we'd guard calls with config checks.
    }

    #[test]
    fn test_otel_layer_feature_gated() {
        #[cfg(feature = "otel")]
        {
            let cfg = test_config();
            let result = build_otel_layer(&cfg);
            // Without endpoint set, should fail.
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
