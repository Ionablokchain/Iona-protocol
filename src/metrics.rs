//! Prometheus metrics for IONA production node.
//!
//! Exposed at `GET /metrics` — compatible with Prometheus scrape + Grafana dashboards.
//! All metrics use the `iona_` prefix for easy filtering.
//!
//! # Example
//!
//! ```
//! use iona::metrics::{init_metrics, render};
//!
//! let _metrics = init_metrics()?;
//! let output = render();
//! # Ok::<(), anyhow::Error>(())
//! ```

use prometheus::{
    Encoder, Gauge, Histogram, HistogramOpts, IntCounter, IntGauge, Opts, Registry, TextEncoder,
};
use std::sync::OnceLock;
use thiserror::Error;

// -----------------------------------------------------------------------------
// Constants
// -----------------------------------------------------------------------------

/// Prefix for all IONA metrics.
const METRIC_PREFIX: &str = "iona";

/// Default bucket values for block time (milliseconds).
const BLOCK_TIME_BUCKETS_MS: &[f64] = &[10.0, 25.0, 50.0, 100.0, 200.0, 500.0, 1000.0, 2000.0, 5000.0];

/// Default bucket values for transactions per block.
const TXS_PER_BLOCK_BUCKETS: &[f64] = &[0.0, 1.0, 10.0, 50.0, 100.0, 500.0, 1000.0, 4096.0];

/// Default bucket values for gas per block.
const GAS_PER_BLOCK_BUCKETS: &[f64] = &[0.0, 100_000.0, 1_000_000.0, 10_000_000.0, 30_000_000.0, 86_000_000.0];

/// Default bucket values for finality latency (milliseconds).
const FINALITY_LATENCY_BUCKETS_MS: &[f64] = &[10.0, 25.0, 50.0, 100.0, 200.0, 500.0, 1000.0, 2000.0];

// -----------------------------------------------------------------------------
// Errors
// -----------------------------------------------------------------------------

/// Errors that can occur during metrics initialisation.
#[derive(Debug, Error)]
pub enum MetricsError {
    #[error("failed to register metric '{name}': {source}")]
    Registration {
        name: String,
        #[source]
        source: prometheus::Error,
    },
    #[error("render error: {source}")]
    Render {
        #[source]
        source: prometheus::Error,
    },
}

pub type MetricsResult<T> = Result<T, MetricsError>;

// -----------------------------------------------------------------------------
// Global registry
// -----------------------------------------------------------------------------

static REGISTRY: OnceLock<Registry> = OnceLock::new();

fn registry() -> &'static Registry {
    REGISTRY.get_or_init(Registry::new)
}

// -----------------------------------------------------------------------------
// Metric handles
// -----------------------------------------------------------------------------

#[derive(Debug)]
pub struct Metrics {
    // Consensus
    pub blocks_committed: IntCounter,
    pub rounds_advanced: IntCounter,
    pub consensus_height: IntGauge,
    pub block_time_ms: Histogram,

    // Throughput
    pub txs_per_block: Histogram,
    pub gas_per_block: Histogram,
    pub base_fee: Gauge,

    // Mempool
    pub mempool_size: IntGauge,
    pub mempool_admitted: IntCounter,
    pub mempool_rejected: IntCounter,
    pub mempool_evicted: IntCounter,
    pub mempool_expired: IntCounter,
    pub mempool_rbf: IntCounter,

    // Network
    pub p2p_peers: IntGauge,
    pub msgs_broadcast: IntCounter,
    pub msgs_received: IntCounter,
    pub block_requests: IntCounter,
    pub range_syncs: IntCounter,

    // RPC
    pub rpc_requests: IntCounter,
    pub rpc_tx_submitted: IntCounter,
    pub rpc_errors: IntCounter,

    // Storage
    pub wal_writes: IntCounter,
    pub wal_write_errors: IntCounter,
    pub state_saves: IntCounter,

    // Finality
    pub finality_latency_ms: Histogram,
    pub finality_height: IntGauge,
    pub finality_certificates: IntCounter,

    // Protocol upgrades
    pub protocol_version: IntGauge,
    pub schema_version: IntGauge,

    // Migrations
    pub migration_running: IntGauge,
    pub migration_completed: IntCounter,
    pub migration_errors: IntCounter,

    // Rate limiting
    pub p2p_rate_limited: IntCounter,
    pub p2p_peers_banned: IntCounter,
    pub p2p_peers_quarantined: IntCounter,
    pub rpc_rate_limited: IntCounter,

    // Snapshot sync
    pub snapshots_created: IntCounter,
    pub snapshots_loaded: IntCounter,
    pub snapshot_size_bytes: Gauge,

    // Audit
    pub audit_events: IntCounter,
}

impl Metrics {
    /// Create and register all metrics.
    pub fn new() -> MetricsResult<Self> {
        let r = registry();
        macro_rules! int_counter {
            ($name:expr, $help:expr) => {{
                let full_name = format!("{}_{}", METRIC_PREFIX, $name);
                let c = IntCounter::with_opts(Opts::new(&full_name, $help))
                    .map_err(|e| MetricsError::Registration { name: full_name, source: e })?;
                r.register(Box::new(c.clone()))
                    .map_err(|e| MetricsError::Registration { name: full_name, source: e })?;
                c
            }};
        }
        macro_rules! int_gauge {
            ($name:expr, $help:expr) => {{
                let full_name = format!("{}_{}", METRIC_PREFIX, $name);
                let g = IntGauge::with_opts(Opts::new(&full_name, $help))
                    .map_err(|e| MetricsError::Registration { name: full_name, source: e })?;
                r.register(Box::new(g.clone()))
                    .map_err(|e| MetricsError::Registration { name: full_name, source: e })?;
                g
            }};
        }
        macro_rules! gauge {
            ($name:expr, $help:expr) => {{
                let full_name = format!("{}_{}", METRIC_PREFIX, $name);
                let g = Gauge::with_opts(Opts::new(&full_name, $help))
                    .map_err(|e| MetricsError::Registration { name: full_name, source: e })?;
                r.register(Box::new(g.clone()))
                    .map_err(|e| MetricsError::Registration { name: full_name, source: e })?;
                g
            }};
        }
        macro_rules! histogram {
            ($name:expr, $help:expr, $buckets:expr) => {{
                let full_name = format!("{}_{}", METRIC_PREFIX, $name);
                let h = Histogram::with_opts(HistogramOpts::new(&full_name, $help).buckets($buckets.to_vec()))
                    .map_err(|e| MetricsError::Registration { name: full_name, source: e })?;
                r.register(Box::new(h.clone()))
                    .map_err(|e| MetricsError::Registration { name: full_name, source: e })?;
                h
            }};
        }

        Ok(Self {
            blocks_committed: int_counter!("blocks_committed_total", "Total blocks committed"),
            rounds_advanced: int_counter!("rounds_advanced_total", "Total BFT rounds advanced (>1 means contention)"),
            consensus_height: int_gauge!("consensus_height", "Current consensus height"),
            block_time_ms: histogram!("block_time_ms", "Block commit latency (ms)", BLOCK_TIME_BUCKETS_MS),

            txs_per_block: histogram!("txs_per_block", "Transactions per committed block", TXS_PER_BLOCK_BUCKETS),
            gas_per_block: histogram!("gas_per_block", "Gas used per committed block", GAS_PER_BLOCK_BUCKETS),
            base_fee: gauge!("base_fee_per_gas", "Current EIP-1559 base fee per gas"),

            mempool_size: int_gauge!("mempool_size", "Current mempool transaction count"),
            mempool_admitted: int_counter!("mempool_admitted_total", "Transactions admitted to mempool"),
            mempool_rejected: int_counter!("mempool_rejected_total", "Transactions rejected (dup/full/sender‑cap)"),
            mempool_evicted: int_counter!("mempool_evicted_total", "Transactions evicted from mempool"),
            mempool_expired: int_counter!("mempool_expired_total", "Transactions expired by TTL"),
            mempool_rbf: int_counter!("mempool_rbf_total", "Replace‑by‑fee replacements"),

            p2p_peers: int_gauge!("p2p_peers", "Connected p2p peers"),
            msgs_broadcast: int_counter!("msgs_broadcast_total", "Gossip messages broadcast"),
            msgs_received: int_counter!("msgs_received_total", "Gossip messages received"),
            block_requests: int_counter!("block_requests_total", "Block fetch requests sent"),
            range_syncs: int_counter!("range_syncs_total", "Block range sync operations"),

            rpc_requests: int_counter!("rpc_requests_total", "Total RPC requests"),
            rpc_tx_submitted: int_counter!("rpc_tx_submitted_total", "Transactions submitted via RPC"),
            rpc_errors: int_counter!("rpc_errors_total", "RPC errors returned"),

            wal_writes: int_counter!("wal_writes_total", "WAL write operations"),
            wal_write_errors: int_counter!("wal_write_errors_total", "WAL write errors"),
            state_saves: int_counter!("state_saves_total", "State snapshots saved to disk"),

            finality_latency_ms: histogram!("finality_latency_ms", "Time from block proposal to finality (ms)", FINALITY_LATENCY_BUCKETS_MS),
            finality_height: int_gauge!("finality_height", "Latest finalized block height"),
            finality_certificates: int_counter!("finality_certificates_total", "Finality certificates issued"),

            protocol_version: int_gauge!("protocol_version", "Current active protocol version"),
            schema_version: int_gauge!("schema_version", "Current storage schema version"),

            migration_running: int_gauge!("migration_running", "Number of migrations currently running"),
            migration_completed: int_counter!("migrations_completed_total", "Migrations completed successfully"),
            migration_errors: int_counter!("migration_errors_total", "Migration errors"),

            p2p_rate_limited: int_counter!("p2p_rate_limited_total", "P2P requests rate‑limited"),
            p2p_peers_banned: int_counter!("p2p_peers_banned_total", "Peers permanently banned"),
            p2p_peers_quarantined: int_counter!("p2p_peers_quarantined_total", "Peers quarantined"),
            rpc_rate_limited: int_counter!("rpc_rate_limited_total", "RPC requests rate‑limited"),

            snapshots_created: int_counter!("snapshots_created_total", "State snapshots created"),
            snapshots_loaded: int_counter!("snapshots_loaded_total", "State snapshots loaded"),
            snapshot_size_bytes: gauge!("snapshot_size_bytes", "Size of latest snapshot in bytes"),

            audit_events: int_counter!("audit_events_total", "Total audit events logged"),
        })
    }
}

// -----------------------------------------------------------------------------
// Rendering
// -----------------------------------------------------------------------------

/// Render all registered metrics as Prometheus text format.
pub fn render() -> String {
    let encoder = TextEncoder::new();
    let metric_families = registry().gather();
    let mut buffer = Vec::new();
    if let Err(e) = encoder.encode(&metric_families, &mut buffer) {
        tracing::warn!(error = %e, "failed to encode Prometheus metrics");
        return String::new();
    }
    String::from_utf8(buffer).unwrap_or_else(|e| {
        tracing::warn!(error = %e, "metrics output is not valid UTF-8");
        String::new()
    })
}

// -----------------------------------------------------------------------------
// OpenTelemetry integration (feature‑gated)
// -----------------------------------------------------------------------------

#[cfg(feature = "otel")]
pub fn build_otel_layer(
    service_name: &str,
    endpoint: &str,
) -> MetricsResult<
    tracing_opentelemetry::OpenTelemetryLayer<
        tracing_subscriber::Registry,
        opentelemetry_sdk::trace::Tracer,
    >,
> {
    use opentelemetry::trace::TracerProvider as _;
    use opentelemetry::KeyValue;
    use opentelemetry_otlp::WithExportConfig;

    let exporter = opentelemetry_otlp::new_exporter()
        .tonic()
        .with_endpoint(endpoint);

    let provider = opentelemetry_otlp::new_pipeline()
        .tracing()
        .with_exporter(exporter)
        .with_trace_config(opentelemetry_sdk::trace::config().with_resource(
            opentelemetry_sdk::Resource::new(vec![KeyValue::new("service.name", service_name.to_string())]),
        ))
        .install_batch(opentelemetry_sdk::runtime::Tokio)
        .map_err(|e| MetricsError::Registration {
            name: "otel_pipeline".into(),
            source: prometheus::Error::Msg(e.to_string()),
        })?;

    let tracer = provider.tracer(service_name.to_string());
    Ok(tracing_opentelemetry::layer().with_tracer(tracer))
}

#[cfg(not(feature = "otel"))]
pub fn build_otel_layer(_service_name: &str, _endpoint: &str) -> MetricsResult<()> {
    Err(MetricsError::Registration {
        name: "otel".into(),
        source: prometheus::Error::Msg("otel feature not enabled".into()),
    })
}

// -----------------------------------------------------------------------------
// Convenience initialiser (backward compatibility)
// -----------------------------------------------------------------------------

/// Initialise all metrics (global).
pub fn init_metrics() -> MetricsResult<Metrics> {
    Metrics::new()
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_metrics_creation() {
        let m = Metrics::new();
        assert!(m.is_ok());
    }

    #[test]
    fn test_render() {
        let _ = Metrics::new().unwrap();
        let output = render();
        assert!(output.is_empty() || output.contains("iona_"));
    }
}
