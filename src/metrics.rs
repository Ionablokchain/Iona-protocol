/// Prometheus metrics for IONA production node.
///
/// Exposed at GET /metrics — compatible with Prometheus scrape + Grafana dashboards.
/// All metrics use the "iona_" prefix for easy filtering.

use prometheus::{
    Gauge, Histogram, HistogramOpts, IntCounter, IntGauge, Opts, Registry, TextEncoder, Encoder,
};
use std::sync::OnceLock;

// ── Global metric registry ────────────────────────────────────────────────

static REGISTRY: OnceLock<Registry> = OnceLock::new();

fn registry() -> &'static Registry {
    REGISTRY.get_or_init(|| Registry::new())
}

// ── Metric handles ─────────────────────────────────────────────────────────

pub struct Metrics {
    // Consensus
    pub blocks_committed:   IntCounter,
    pub rounds_advanced:    IntCounter,
    pub consensus_height:   IntGauge,
    pub block_time_ms:      Histogram,   // time from propose to commit

    // Throughput
    pub txs_per_block:      Histogram,
    pub gas_per_block:      Histogram,
    pub base_fee:           Gauge,

    // Mempool
    pub mempool_size:       IntGauge,
    pub mempool_admitted:   IntCounter,
    pub mempool_rejected:   IntCounter,
    pub mempool_evicted:    IntCounter,
    pub mempool_expired:    IntCounter,
    pub mempool_rbf:        IntCounter,

    // Network
    pub p2p_peers:          IntGauge,
    pub msgs_broadcast:     IntCounter,
    pub msgs_received:      IntCounter,
    pub block_requests:     IntCounter,
    pub range_syncs:        IntCounter,

    // RPC
    pub rpc_requests:       IntCounter,
    pub rpc_tx_submitted:   IntCounter,
    pub rpc_errors:         IntCounter,

    // Storage
    pub wal_writes:         IntCounter,
    pub wal_write_errors:   IntCounter,
    pub state_saves:        IntCounter,

    // Finality
    pub finality_latency_ms: Histogram,
    pub finality_height:     IntGauge,
    pub finality_certificates: IntCounter,

    // Protocol upgrades
    pub protocol_version:    IntGauge,
    pub schema_version:      IntGauge,

    // Migrations
    pub migration_running:   IntGauge,
    pub migration_completed: IntCounter,
    pub migration_errors:    IntCounter,

    // Rate limiting
    pub p2p_rate_limited:    IntCounter,
    pub p2p_peers_banned:    IntCounter,
    pub p2p_peers_quarantined: IntCounter,
    pub rpc_rate_limited:    IntCounter,

    // Snapshot sync
    pub snapshots_created:   IntCounter,
    pub snapshots_loaded:    IntCounter,
    pub snapshot_size_bytes: Gauge,

    // Audit
    pub audit_events:        IntCounter,
}

impl Metrics {
    pub fn new() -> anyhow::Result<Self> {
        let r = registry();
        macro_rules! int_counter {
            ($name:expr, $help:expr) => {{
                let c = IntCounter::with_opts(Opts::new($name, $help))?;
                r.register(Box::new(c.clone()))?;
                c
            }};
        }
        macro_rules! int_gauge {
            ($name:expr, $help:expr) => {{
                let g = IntGauge::with_opts(Opts::new($name, $help))?;
                r.register(Box::new(g.clone()))?;
                g
            }};
        }
        macro_rules! gauge {
            ($name:expr, $help:expr) => {{
                let g = Gauge::with_opts(Opts::new($name, $help))?;
                r.register(Box::new(g.clone()))?;
                g
            }};
        }
        macro_rules! histogram {
            ($name:expr, $help:expr, $buckets:expr) => {{
                let h = Histogram::with_opts(HistogramOpts::new($name, $help).buckets($buckets))?;
                r.register(Box::new(h.clone()))?;
                h
            }};
        }

        Ok(Self {
            blocks_committed: int_counter!("iona_blocks_committed_total", "Total blocks committed"),
            rounds_advanced:  int_counter!("iona_rounds_advanced_total", "Total BFT rounds advanced (>1 means contention)"),
            consensus_height: int_gauge!("iona_consensus_height", "Current consensus height"),
            block_time_ms:    histogram!("iona_block_time_ms", "Block commit latency (ms)",
                vec![10.0, 25.0, 50.0, 100.0, 200.0, 500.0, 1000.0, 2000.0, 5000.0]),

            txs_per_block: histogram!("iona_txs_per_block", "Transactions per committed block",
                vec![0.0, 1.0, 10.0, 50.0, 100.0, 500.0, 1000.0, 4096.0]),
            gas_per_block:  histogram!("iona_gas_per_block", "Gas used per committed block",
                vec![0.0, 100_000.0, 1_000_000.0, 10_000_000.0, 30_000_000.0, 86_000_000.0]),
            base_fee:       gauge!("iona_base_fee_per_gas", "Current EIP-1559 base fee per gas"),

            mempool_size:     int_gauge!("iona_mempool_size", "Current mempool transaction count"),
            mempool_admitted: int_counter!("iona_mempool_admitted_total", "Transactions admitted to mempool"),
            mempool_rejected: int_counter!("iona_mempool_rejected_total", "Transactions rejected (dup/full/sender-cap)"),
            mempool_evicted:  int_counter!("iona_mempool_evicted_total", "Transactions evicted from mempool"),
            mempool_expired:  int_counter!("iona_mempool_expired_total", "Transactions expired by TTL"),
            mempool_rbf:      int_counter!("iona_mempool_rbf_total", "Replace-by-fee replacements"),

            p2p_peers:        int_gauge!("iona_p2p_peers", "Connected p2p peers"),
            msgs_broadcast:   int_counter!("iona_msgs_broadcast_total", "Gossip messages broadcast"),
            msgs_received:    int_counter!("iona_msgs_received_total", "Gossip messages received"),
            block_requests:   int_counter!("iona_block_requests_total", "Block fetch requests sent"),
            range_syncs:      int_counter!("iona_range_syncs_total", "Block range sync operations"),

            rpc_requests:     int_counter!("iona_rpc_requests_total", "Total RPC requests"),
            rpc_tx_submitted: int_counter!("iona_rpc_tx_submitted_total", "Transactions submitted via RPC"),
            rpc_errors:       int_counter!("iona_rpc_errors_total", "RPC errors returned"),

            wal_writes:       int_counter!("iona_wal_writes_total", "WAL write operations"),
            wal_write_errors: int_counter!("iona_wal_write_errors_total", "WAL write errors"),
            state_saves:      int_counter!("iona_state_saves_total", "State snapshots saved to disk"),

            finality_latency_ms: histogram!("iona_finality_latency_ms", "Time from block proposal to finality (ms)",
                vec![10.0, 25.0, 50.0, 100.0, 200.0, 500.0, 1000.0, 2000.0]),
            finality_height:     int_gauge!("iona_finality_height", "Latest finalized block height"),
            finality_certificates: int_counter!("iona_finality_certificates_total", "Finality certificates issued"),

            protocol_version:    int_gauge!("iona_protocol_version", "Current active protocol version"),
            schema_version:      int_gauge!("iona_schema_version", "Current storage schema version"),

            migration_running:   int_gauge!("iona_migration_running", "Number of migrations currently running"),
            migration_completed: int_counter!("iona_migrations_completed_total", "Migrations completed successfully"),
            migration_errors:    int_counter!("iona_migration_errors_total", "Migration errors"),

            p2p_rate_limited:      int_counter!("iona_p2p_rate_limited_total", "P2P requests rate-limited"),
            p2p_peers_banned:      int_counter!("iona_p2p_peers_banned_total", "Peers permanently banned"),
            p2p_peers_quarantined: int_counter!("iona_p2p_peers_quarantined_total", "Peers quarantined"),
            rpc_rate_limited:      int_counter!("iona_rpc_rate_limited_total", "RPC requests rate-limited"),

            snapshots_created:   int_counter!("iona_snapshots_created_total", "State snapshots created"),
            snapshots_loaded:    int_counter!("iona_snapshots_loaded_total", "State snapshots loaded"),
            snapshot_size_bytes: gauge!("iona_snapshot_size_bytes", "Size of latest snapshot in bytes"),

            audit_events:        int_counter!("iona_audit_events_total", "Total audit events logged"),
        })
    }
}

/// Render all registered metrics as Prometheus text format.
pub fn render() -> String {
    let encoder = TextEncoder::new();
    let metric_families = registry().gather();
    let mut out = Vec::new();
    encoder.encode(&metric_families, &mut out).unwrap_or_default();
    String::from_utf8(out).unwrap_or_default()
}

// ── Optional OpenTelemetry ───────────────────────────────────────────────

#[cfg(feature = "otel")]
pub fn build_otel_layer(
    service_name: &str,
    endpoint: &str,
) -> anyhow::Result<tracing_opentelemetry::OpenTelemetryLayer<tracing_subscriber::Registry, opentelemetry::sdk::trace::Tracer>> {
    use opentelemetry::KeyValue;
    use opentelemetry_otlp::WithExportConfig;
    use opentelemetry::trace::TracerProvider as _;

    let exporter = opentelemetry_otlp::new_exporter()
        .tonic()
        .with_endpoint(endpoint);

    let provider = opentelemetry_otlp::new_pipeline()
        .tracing()
        .with_exporter(exporter)
        .with_trace_config(
            opentelemetry::sdk::trace::config().with_resource(opentelemetry::sdk::Resource::new(vec![
                KeyValue::new("service.name", service_name.to_string()),
            ])),
        )
        .install_batch(opentelemetry::sdk::runtime::Tokio)?;

    let tracer = provider.tracer(service_name.to_string());
    Ok(tracing_opentelemetry::layer().with_tracer(tracer))
}

#[cfg(not(feature = "otel"))]
pub fn build_otel_layer(
    _service_name: &str,
    _endpoint: &str,
) -> anyhow::Result<()> {
    anyhow::bail!("otel feature not enabled")
}
