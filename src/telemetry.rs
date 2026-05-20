//! IONA— OpenTelemetry distributed tracing.
//!
//! Initializes OTLP tracing export to Jaeger, Tempo, or any
//! OpenTelemetry-compatible collector. Enables end-to-end request
//! tracing across consensus, EVM execution, P2P, and RPC layers.
//!
//! # Configuration
//! Set `OTEL_EXPORTER_OTLP_ENDPOINT` environment variable, e.g.:
//!   `OTEL_EXPORTER_OTLP_ENDPOINT=http://localhost:4317 iona-node`
//!
//! Or in config.toml:
//!   [observability]
//!   otlp_endpoint = "http://jaeger:4317"
//!   service_name  = "iona-node"

use tracing::Level;

/// Initialize the tracing subscriber with optional OTLP export.
/// Call once at node startup before any tracing spans.
pub fn init_tracing(
    log_level: &str,
    log_format: &str,  // "text" or "json"
    otlp_endpoint: Option<&str>,
    service_name: &str,
) -> anyhow::Result<Option<OtelGuard>> {
    use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt, EnvFilter};

    let level = match log_level.to_lowercase().as_str() {
        "trace" => Level::TRACE,
        "debug" => Level::DEBUG,
        "warn"  => Level::WARN,
        "error" => Level::ERROR,
        _       => Level::INFO,
    };

    let env_filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new(log_level));

    // Base fmt layer
    let fmt_layer = tracing_subscriber::fmt::layer()
        .with_target(true)
        .with_thread_ids(false);

    // JSON or text format
    let subscriber = tracing_subscriber::registry()
        .with(env_filter);

    // If OTLP endpoint configured, add OTLP layer
    #[cfg(feature = "opentelemetry")]
    if let Some(endpoint) = otlp_endpoint {
        use opentelemetry_otlp::WithExportConfig;
        use opentelemetry_sdk::runtime;

        let otlp_exporter = opentelemetry_otlp::new_exporter()
            .tonic()
            .with_endpoint(endpoint);

        let tracer = opentelemetry_otlp::new_pipeline()
            .tracing()
            .with_exporter(otlp_exporter)
            .with_trace_config(
                opentelemetry_sdk::trace::config()
                    .with_resource(opentelemetry_sdk::Resource::new(vec![
                        opentelemetry::KeyValue::new("service.name", service_name.to_string()),
                        opentelemetry::KeyValue::new("service.version", "35.0.0"),
                    ]))
            )
            .install_batch(runtime::Tokio)?;

        let otel_layer = tracing_opentelemetry::layer().with_tracer(tracer);
        if log_format == "json" {
            subscriber
                .with(fmt_layer.json())
                .with(otel_layer)
                .init();
        } else {
            subscriber
                .with(fmt_layer)
                .with(otel_layer)
                .init();
        }
        tracing::info!(endpoint = %endpoint, service = service_name, "OTLP tracing initialized");
        return Ok(Some(OtelGuard));
    }

    // No OTLP — standard logging only
    if log_format == "json" {
        subscriber.with(fmt_layer).init();
    } else {
        subscriber.with(fmt_layer).init();
    }
    Ok(None)
}

/// Guard that flushes OTLP spans on drop (at node shutdown).
pub struct OtelGuard;

impl Drop for OtelGuard {
    fn drop(&mut self) {
        #[cfg(feature = "opentelemetry")]
        opentelemetry::global::shutdown_tracer_provider();
        tracing::info!("OTLP tracer flushed and shut down");
    }
}

/// Key span attributes used across IONA components.
pub mod attrs {
    pub const HEIGHT:       &str = "consensus.height";
    pub const ROUND:        &str = "consensus.round";
    pub const CHAIN_ID:     &str = "chain.id";
    pub const TX_HASH:      &str = "tx.hash";
    pub const GAS_USED:     &str = "evm.gas_used";
    pub const PEER_ID:      &str = "p2p.peer_id";
    pub const BLOCK_TIME_MS:&str = "consensus.block_time_ms";
}
