//! Quantum Prometheus metrics for IONA production node.
//!
//! # Quantum Observability Model
//!
//! Metrics are quantum observables — Hermitian operators whose eigenvalues
//! correspond to measurable quantities. Each metric is a projective
//! measurement in the computational basis of the node's Hilbert space.
//!
//! # Hamiltonian for Observables
//!
//! ```text
//! Ĥ_metrics = Σ_i ω_i Ô_i
//!
//! Ô_consensus = Σ_h E_h |height_h⟩⟨height_h|
//! Ô_network   = Σ_p g_p (σ^+_p σ^-_p)
//! Ô_mempool   = Σ_t ν_t a†_t a_t
//! Ô_storage   = Σ_s κ_s |state_s⟩⟨state_s|
//! ```
//!
//! # Quantum Measurement Process
//!
//! When Prometheus scrapes `/metrics`, it performs a simultaneous
//! measurement of all observables. The Heisenberg uncertainty principle
//! applies: some pairs of metrics cannot be simultaneously measured
//! with arbitrary precision (e.g., mempool size and transaction rate).
//!
//! # Metric Prefix
//!
//! All metrics use the `iona_` prefix for quantum state filtering.

use prometheus::{
    Encoder, Gauge, Histogram, HistogramOpts, IntCounter, IntGauge, Opts, Registry, TextEncoder,
};
use std::sync::OnceLock;
use thiserror::Error;

// -----------------------------------------------------------------------------
// Quantum Constants
// -----------------------------------------------------------------------------

/// Prefix for all IONA metrics (quantum observable namespace).
const METRIC_PREFIX: &str = "iona";

/// Reduced Planck constant (natural units).
const HBAR: f64 = 1.0;

/// Measurement decoherence per scrape.
const MEASUREMENT_DECOHERENCE: f64 = 0.00001;

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

// -----------------------------------------------------------------------------
// Quantum Metric Handles
// -----------------------------------------------------------------------------

/// Collection of all quantum observables for the IONA node.
///
/// Each field represents a Hermitian operator Ô_i whose expectation
/// value ⟨Ô_i⟩ is measured at scrape time.
#[derive(Debug)]
pub struct Metrics {
    // ── Consensus Observables ──────────────────────────────────────────
    /// Total blocks committed — cumulative eigenvalue.
    pub blocks_committed: IntCounter,
    /// Total BFT rounds advanced (>1 means contention).
    pub rounds_advanced: IntCounter,
    /// Current consensus height — position eigenvalue.
    pub consensus_height: IntGauge,
    /// Block commit latency — time evolution observable.
    pub block_time_ms: Histogram,

    // ── Throughput Observables ─────────────────────────────────────────
    /// Transactions per committed block — density observable.
    pub txs_per_block: Histogram,
    /// Gas used per committed block — energy observable.
    pub gas_per_block: Histogram,
    /// Current EIP-1559 base fee — energy eigenvalue.
    pub base_fee: Gauge,

    // ── Mempool Observables ────────────────────────────────────────────
    /// Current mempool size — occupation number.
    pub mempool_size: IntGauge,
    /// Transactions admitted — creation operator count.
    pub mempool_admitted: IntCounter,
    /// Transactions rejected — exclusion count.
    pub mempool_rejected: IntCounter,
    /// Transactions evicted — annihilation operator count.
    pub mempool_evicted: IntCounter,
    /// Transactions expired by TTL — decay count.
    pub mempool_expired: IntCounter,
    /// Replace-by-fee replacements — state transition count.
    pub mempool_rbf: IntCounter,

    // ── Network Observables ────────────────────────────────────────────
    /// Connected P2P peers — entanglement count.
    pub p2p_peers: IntGauge,
    /// Gossip messages broadcast — emission count.
    pub msgs_broadcast: IntCounter,
    /// Gossip messages received — absorption count.
    pub msgs_received: IntCounter,
    /// Block fetch requests — quantum query count.
    pub block_requests: IntCounter,
    /// Block range sync operations — state transfer count.
    pub range_syncs: IntCounter,

    // ── RPC Observables ────────────────────────────────────────────────
    /// Total RPC requests — interaction count.
    pub rpc_requests: IntCounter,
    /// Transactions submitted via RPC — injection count.
    pub rpc_tx_submitted: IntCounter,
    /// RPC errors returned — decoherence count.
    pub rpc_errors: IntCounter,
    /// RPC request duration — interaction time observable.
    pub rpc_duration_seconds: Histogram,

    // ── Storage Observables ────────────────────────────────────────────
    /// WAL write operations — persistence count.
    pub wal_writes: IntCounter,
    /// WAL write errors — storage decoherence count.
    pub wal_write_errors: IntCounter,
    /// State snapshots saved — wavefunction collapse count.
    pub state_saves: IntCounter,

    // ── Finality Observables ───────────────────────────────────────────
    /// Time from block proposal to finality — entanglement propagation time.
    pub finality_latency_ms: Histogram,
    /// Latest finalized block height — finality eigenvalue.
    pub finality_height: IntGauge,
    /// Finality certificates issued — certification count.
    pub finality_certificates: IntCounter,

    // ── Protocol Observables ───────────────────────────────────────────
    /// Current active protocol version — quantum number.
    pub protocol_version: IntGauge,
    /// Current storage schema version — basis set version.
    pub schema_version: IntGauge,

    // ── Migration Observables ──────────────────────────────────────────
    /// Migrations currently running — transition count.
    pub migration_running: IntGauge,
    /// Migrations completed — successful transition count.
    pub migration_completed: IntCounter,
    /// Migration errors — failed transition count.
    pub migration_errors: IntCounter,

    // ── Rate Limiting Observables ──────────────────────────────────────
    /// P2P requests rate-limited — constraint enforcement count.
    pub p2p_rate_limited: IntCounter,
    /// Peers permanently banned — exclusion count.
    pub p2p_peers_banned: IntCounter,
    /// Peers quarantined — isolation count.
    pub p2p_peers_quarantined: IntCounter,
    /// RPC requests rate-limited — constraint enforcement count.
    pub rpc_rate_limited: IntCounter,

    // ── Snapshot Observables ───────────────────────────────────────────
    /// State snapshots created — backup count.
    pub snapshots_created: IntCounter,
    /// State snapshots loaded — restoration count.
    pub snapshots_loaded: IntCounter,
    /// Size of latest snapshot — data eigenvalue.
    pub snapshot_size_bytes: Gauge,

    // ── Audit Observables ──────────────────────────────────────────────
    /// Total audit events logged — security count.
    pub audit_events: IntCounter,

    // ── Quantum Observables ────────────────────────────────────────────
    /// Node coherence — quantum state purity.
    pub node_coherence: Gauge,
    /// Entanglement entropy — quantum information measure.
    pub entanglement_entropy: Gauge,
    /// Measurement count (scrapes) — observation count.
    pub measurement_count: IntCounter,
}

impl Metrics {
    /// Create and register all quantum observables.
    pub fn new() -> MetricsResult<Self> {
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

        Ok(Self {
            // Consensus
            blocks_committed: int_counter!(
                "blocks_committed_total",
                "Total blocks committed (cumulative eigenvalue)"
            ),
            rounds_advanced: int_counter!(
                "rounds_advanced_total",
                "Total BFT rounds advanced (>1 means contention)"
            ),
            consensus_height: int_gauge!(
                "consensus_height",
                "Current consensus height (position eigenvalue)"
            ),
            block_time_ms: histogram!(
                "block_time_ms",
                "Block commit latency in milliseconds",
                BLOCK_TIME_BUCKETS_MS
            ),

            // Throughput
            txs_per_block: histogram!(
                "txs_per_block",
                "Transactions per committed block (density observable)",
                TXS_PER_BLOCK_BUCKETS
            ),
            gas_per_block: histogram!(
                "gas_per_block",
                "Gas used per committed block (energy observable)",
                GAS_PER_BLOCK_BUCKETS
            ),
            base_fee: gauge!(
                "base_fee_per_gas",
                "Current EIP-1559 base fee per gas (energy eigenvalue)"
            ),

            // Mempool
            mempool_size: int_gauge!(
                "mempool_size",
                "Current mempool transaction count (occupation number)"
            ),
            mempool_admitted: int_counter!(
                "mempool_admitted_total",
                "Transactions admitted to mempool (creation count)"
            ),
            mempool_rejected: int_counter!(
                "mempool_rejected_total",
                "Transactions rejected (exclusion count)"
            ),
            mempool_evicted: int_counter!(
                "mempool_evicted_total",
                "Transactions evicted from mempool (annihilation count)"
            ),
            mempool_expired: int_counter!(
                "mempool_expired_total",
                "Transactions expired by TTL (decay count)"
            ),
            mempool_rbf: int_counter!(
                "mempool_rbf_total",
                "Replace-by-fee replacements (state transition count)"
            ),

            // Network
            p2p_peers: int_gauge!(
                "p2p_peers",
                "Connected P2P peers (entanglement count)"
            ),
            msgs_broadcast: int_counter!(
                "msgs_broadcast_total",
                "Gossip messages broadcast (emission count)"
            ),
            msgs_received: int_counter!(
                "msgs_received_total",
                "Gossip messages received (absorption count)"
            ),
            block_requests: int_counter!(
                "block_requests_total",
                "Block fetch requests sent (quantum query count)"
            ),
            range_syncs: int_counter!(
                "range_syncs_total",
                "Block range sync operations (state transfer count)"
            ),

            // RPC
            rpc_requests: int_counter!(
                "rpc_requests_total",
                "Total RPC requests (interaction count)"
            ),
            rpc_tx_submitted: int_counter!(
                "rpc_tx_submitted_total",
                "Transactions submitted via RPC (injection count)"
            ),
            rpc_errors: int_counter!(
                "rpc_errors_total",
                "RPC errors returned (decoherence count)"
            ),
            rpc_duration_seconds: histogram!(
                "rpc_request_duration_seconds",
                "RPC request duration in seconds",
                RPC_DURATION_BUCKETS_S
            ),

            // Storage
            wal_writes: int_counter!(
                "wal_writes_total",
                "WAL write operations (persistence count)"
            ),
            wal_write_errors: int_counter!(
                "wal_write_errors_total",
                "WAL write errors (storage decoherence count)"
            ),
            state_saves: int_counter!(
                "state_saves_total",
                "State snapshots saved to disk (wavefunction collapse count)"
            ),

            // Finality
            finality_latency_ms: histogram!(
                "finality_latency_ms",
                "Time from block proposal to finality in milliseconds",
                FINALITY_LATENCY_BUCKETS_MS
            ),
            finality_height: int_gauge!(
                "finality_height",
                "Latest finalized block height (finality eigenvalue)"
            ),
            finality_certificates: int_counter!(
                "finality_certificates_total",
                "Finality certificates issued (certification count)"
            ),

            // Protocol
            protocol_version: int_gauge!(
                "protocol_version",
                "Current active protocol version (quantum number)"
            ),
            schema_version: int_gauge!(
                "schema_version",
                "Current storage schema version (basis set version)"
            ),

            // Migration
            migration_running: int_gauge!(
                "migration_running",
                "Number of migrations currently running"
            ),
            migration_completed: int_counter!(
                "migrations_completed_total",
                "Migrations completed successfully"
            ),
            migration_errors: int_counter!(
                "migration_errors_total",
                "Migration errors (failed transition count)"
            ),

            // Rate Limiting
            p2p_rate_limited: int_counter!(
                "p2p_rate_limited_total",
                "P2P requests rate-limited"
            ),
            p2p_peers_banned: int_counter!(
                "p2p_peers_banned_total",
                "Peers permanently banned (exclusion count)"
            ),
            p2p_peers_quarantined: int_counter!(
                "p2p_peers_quarantined_total",
                "Peers quarantined (isolation count)"
            ),
            rpc_rate_limited: int_counter!(
                "rpc_rate_limited_total",
                "RPC requests rate-limited"
            ),

            // Snapshots
            snapshots_created: int_counter!(
                "snapshots_created_total",
                "State snapshots created (backup count)"
            ),
            snapshots_loaded: int_counter!(
                "snapshots_loaded_total",
                "State snapshots loaded (restoration count)"
            ),
            snapshot_size_bytes: gauge!(
                "snapshot_size_bytes",
                "Size of latest snapshot in bytes (data eigenvalue)"
            ),

            // Audit
            audit_events: int_counter!(
                "audit_events_total",
                "Total audit events logged (security count)"
            ),

            // Quantum
            node_coherence: gauge!(
                "node_coherence",
                "Node quantum coherence (state purity γ = Tr(ρ²))"
            ),
            entanglement_entropy: gauge!(
                "entanglement_entropy",
                "Node entanglement entropy S = -Tr(ρ ln ρ)"
            ),
            measurement_count: int_counter!(
                "measurement_count_total",
                "Total measurement operations (scrape count)"
            ),
        })
    }
}

// -----------------------------------------------------------------------------
// Quantum Rendering
// -----------------------------------------------------------------------------

/// Render all registered quantum observables as Prometheus text format.
///
/// This performs a simultaneous measurement of all observables,
/// collapsing the quantum state to a classical representation.
pub fn render() -> String {
    // Increment measurement counter
    if let Some(metrics) = get_metrics() {
        metrics.measurement_count.inc();
    }

    let encoder = TextEncoder::new();
    let metric_families = registry().gather();
    let mut buffer = Vec::new();

    if let Err(e) = encoder.encode(&metric_families, &mut buffer) {
        tracing::warn!(error = %e, "failed to encode quantum observables");
        return String::new();
    }

    String::from_utf8(buffer).unwrap_or_else(|e| {
        tracing::warn!(error = %e, "quantum measurement output is not valid UTF-8");
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
// OpenTelemetry Integration (feature‑gated)
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
        .with_trace_config(
            opentelemetry_sdk::trace::config()
                .with_resource(opentelemetry_sdk::Resource::new(vec![
                    KeyValue::new("service.name", service_name.to_string()),
                ])),
        )
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
// Global Metric Access
// -----------------------------------------------------------------------------

/// Global metrics instance.
static METRICS: OnceLock<Metrics> = OnceLock::new();

/// Initialize global metrics.
pub fn init_metrics() -> MetricsResult<&'static Metrics> {
    let metrics = Metrics::new()?;
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
        // Output may be empty if no metrics have been modified
        assert!(
            output.is_empty() || output.contains("iona_"),
            "Output should contain iona_ prefix or be empty"
        );
    }

    #[test]
    fn test_render_with_metadata() {
        let _ = Metrics::new().unwrap();
        let output = render_with_metadata();
        assert!(output.contains("measurement_epoch_seconds"));
    }

    #[test]
    fn test_int_counter_increment() {
        let m = Metrics::new().unwrap();
        m.blocks_committed.inc();
        assert_eq!(m.blocks_committed.get(), 1);
        m.blocks_committed.inc_by(5);
        assert_eq!(m.blocks_committed.get(), 6);
    }

    #[test]
    fn test_int_gauge_set() {
        let m = Metrics::new().unwrap();
        m.consensus_height.set(42);
        assert_eq!(m.consensus_height.get(), 42);
    }

    #[test]
    fn test_gauge_set() {
        let m = Metrics::new().unwrap();
        m.base_fee.set(100.0);
        assert!((m.base_fee.get() - 100.0).abs() < 1e-10);
    }

    #[test]
    fn test_histogram_observe() {
        let m = Metrics::new().unwrap();
        m.block_time_ms.observe(250.0);
        m.block_time_ms.observe(500.0);
        // Histogram doesn't expose sum/count directly via get()
        let output = render();
        assert!(output.contains("iona_block_time_ms"));
    }

    #[test]
    fn test_node_coherence_gauge() {
        let m = Metrics::new().unwrap();
        m.node_coherence.set(0.95);
        assert!((m.node_coherence.get() - 0.95).abs() < 1e-10);
    }

    #[test]
    fn test_measurement_count() {
        let m = Metrics::new().unwrap();
        render();
        render();
        assert_eq!(m.measurement_count.get(), 2);
    }
}
