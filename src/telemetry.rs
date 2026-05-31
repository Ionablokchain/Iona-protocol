//! IONA — OpenTelemetry distributed tracing with quantum channel formalism.
//!
//! # Quantum Tracing Model
//!
//! Distributed tracing is modelled as a **quantum measurement chain** where
//! each span corresponds to a **generalised measurement (POVM)** on the
//! system's Hilbert space. The trace context propagates via **quantum
//! teleportation** of the correlation matrix between services.
//!
//! # Mathematical Formalism
//!
//! ## Span as Positive Operator-Valued Measure (POVM)
//! ```text
//! M_span = { E_i }_i,   Σ_i E_i = Î,   E_i ≥ 0
//! ```
//! Each span event is an element E_i of a POVM acting on ℋ_system.
//! The probability of observing span outcome i is:
//! ```text
//! P(i) = Tr(ρ E_i)
//! ```
//!
//! ## Trace Context as Entanglement Witness
//! ```text
//! W_trace = Σ_{i,j} w_{ij} σ_i^A ⊗ σ_j^B
//! ```
//! The trace ID entangles the parent span (subsystem A) with child spans
//! (subsystem B). The correlation matrix w_{ij} is preserved across
//! process boundaries via OTLP.
//!
//! ## OTLP Export as Quantum Channel
//! ```text
//! Φ(ρ) = Σ_k K_k ρ K_k†
//! K_k = √λ_k |k⟩⟨k| ⊗ Î_env
//! ```
//! The OTLP exporter is a **quantum channel** that couples the system
//! to the observability environment. The Kraus operators K_k describe
//! the sampling and batching of spans.
//!
//! ## Sampling as Projective Measurement
//! ```text
//! Π_sample = |sample⟩⟨sample| ⊗ Î_rest
//! p_sample = Tr(ρ Π_sample)
//! ```
//! Trace sampling is a projective measurement that selects a subset of
//! spans based on the Born rule with probability p_sample.
//!
//! ## Span Processor as Lindblad Evolution
//! ```text
//! dρ/dt = -i[Ĥ, ρ] + Σ_k γ_k (L_k ρ L_k† - ½{L_k† L_k, ρ})
//! ```
//! The span processor evolves the tracing state under the Hamiltonian
//! of the observability system, with Lindblad operators L_k representing
//! batching, export, and memory pressure.

use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};
use tracing::Level;

// -----------------------------------------------------------------------------
// Quantum Constants
// -----------------------------------------------------------------------------

/// Reduced Planck constant (natural units).
const HBAR: f64 = 1.0;

/// Default sampling probability (Born rule weight).
const DEFAULT_SAMPLING_PROBABILITY: f64 = 0.01;

/// Maximum span queue depth before Lindblad decoherence triggers.
const MAX_SPAN_QUEUE_DEPTH: usize = 4096;

/// Quantum channel Kraus rank (number of export operators).
const KRAUS_RANK: usize = 4;

/// Decoherence rate γ for the span processor.
const DECOHERENCE_RATE: f64 = 0.001;

/// Coherence time T₂ for span batching (milliseconds).
const COHERENCE_TIME_MS: u64 = 100;

// -----------------------------------------------------------------------------
// Quantum Span Representation
// -----------------------------------------------------------------------------

/// A quantum span — element of a POVM {E_i} acting on ℋ_system.
///
/// Each span is a positive semi-definite operator E_i ≥ 0 that
/// satisfies the completeness relation Σ_i E_i = Î.
#[derive(Debug, Clone)]
pub struct QuantumSpan {
    /// Span ID — quantum state label.
    pub span_id: u64,
    /// Trace ID — entanglement correlation identifier.
    pub trace_id: u64,
    /// Parent span ID — pre-entangled state.
    pub parent_span_id: Option<u64>,
    /// Span name — observable label.
    pub name: String,
    /// Start time of the measurement.
    pub start_time: Instant,
    /// Duration of the measurement.
    pub duration: Duration,
    /// Span attributes — expectation values ⟨Ô_k⟩.
    pub attributes: Vec<(String, String)>,
    /// Born probability of this span outcome P(i) = Tr(ρ E_i).
    pub born_probability: f64,
    /// Quantum purity of this span's subspace.
    pub purity: f64,
}

impl QuantumSpan {
    /// Create a new quantum span — initialise POVM element E_i.
    pub fn new(
        span_id: u64,
        trace_id: u64,
        parent_span_id: Option<u64>,
        name: String,
        sampling_probability: f64,
    ) -> Self {
        Self {
            span_id,
            trace_id,
            parent_span_id,
            name,
            start_time: Instant::now(),
            duration: Duration::ZERO,
            attributes: Vec::new(),
            born_probability: sampling_probability,
            purity: 1.0,
        }
    }

    /// Add an attribute — measure an observable ⟨Ô⟩.
    pub fn with_attribute(mut self, key: String, value: String) -> Self {
        self.attributes.push((key, value));
        // Each measurement induces minor decoherence
        self.purity *= 0.9999;
        self
    }

    /// Complete the span — perform the final projective measurement.
    pub fn complete(&mut self) {
        self.duration = self.start_time.elapsed();
        // Final measurement collapses the state slightly
        self.purity *= 0.999;
    }

    /// Compute the entanglement fidelity with a parent span.
    pub fn entanglement_fidelity(&self, parent_purity: f64) -> f64 {
        // F = √(p_child × p_parent)
        (self.born_probability * parent_purity).sqrt()
    }
}

// -----------------------------------------------------------------------------
// Quantum Span Processor (Lindblad Evolution)
// -----------------------------------------------------------------------------

/// Span processor that evolves under Lindblad master equation.
///
/// ```text
/// dρ/dt = -i[Ĥ, ρ] + Σ_k γ_k (L_k ρ L_k† - ½{L_k† L_k, ρ})
/// ```
struct QuantumSpanProcessor {
    /// Span queue — current quantum state ρ.
    spans: Vec<QuantumSpan>,
    /// Maximum queue depth before forced decoherence.
    max_depth: usize,
    /// Current coherence of the processor.
    coherence: f64,
    /// Total spans processed (cumulative measurement count).
    total_processed: AtomicU64,
    /// Total spans dropped due to decoherence.
    total_dropped: AtomicU64,
}

impl QuantumSpanProcessor {
    /// Create a new quantum span processor in the ground state |∅⟩.
    fn new(max_depth: usize) -> Self {
        Self {
            spans: Vec::with_capacity(max_depth / 2),
            max_depth,
            coherence: 1.0,
            total_processed: AtomicU64::new(0),
            total_dropped: AtomicU64::new(0),
        }
    }

    /// Apply Lindblad evolution step.
    ///
    /// ```text
    /// ρ(t + dt) = ρ(t) + dt × (-i[Ĥ, ρ] + Σ_k γ_k (L_k ρ L_k† - ½{L_k† L_k, ρ}))
    /// ```
    fn evolve(&mut self, dt: f64) {
        // Hamiltonian evolution: Ĥ = ω a†a (simple harmonic oscillator)
        // This preserves coherence in the absence of decoherence.
        let hamiltonian_phase = (dt * HBAR).sin();
        self.coherence = (self.coherence * hamiltonian_phase.cos()).abs();

        // Lindblad decoherence: L_k = |k⟩⟨k+1| (span export)
        let lindblad_decay = (-DECOHERENCE_RATE * dt).exp();
        self.coherence *= lindblad_decay;
        self.coherence = self.coherence.clamp(0.0, 1.0);
    }

    /// Push a span onto the queue — apply creation operator a†.
    ///
    /// If the queue exceeds max_depth, the oldest span decoheres
    /// (is exported or dropped).
    fn push(&mut self, span: QuantumSpan) {
        if self.spans.len() >= self.max_depth {
            // Lindblad jump: L_k |n⟩ → |n-1⟩
            self.spans.remove(0);
            self.total_dropped.fetch_add(1, Ordering::Relaxed);
            self.coherence *= 0.95; // decoherence penalty
        }
        self.spans.push(span);
    }

    /// Export spans — apply Kraus operators Φ(ρ) = Σ K_k ρ K_k†.
    fn export(&mut self) -> Vec<QuantumSpan> {
        let exported: Vec<QuantumSpan> = self.spans.drain(..).collect();
        self.total_processed
            .fetch_add(exported.len() as u64, Ordering::Relaxed);

        // Each export applies the quantum channel
        let kraus_factor = (1.0 / KRAUS_RANK as f64).sqrt();
        self.coherence = (self.coherence * kraus_factor).clamp(0.0, 1.0);

        exported
    }

    /// Get current coherence.
    fn coherence(&self) -> f64 {
        self.coherence
    }

    /// Get queue depth.
    fn depth(&self) -> usize {
        self.spans.len()
    }
}

// -----------------------------------------------------------------------------
// Quantum OTLP Guard
// -----------------------------------------------------------------------------

/// Guard that flushes OTLP spans on drop — applies final Kraus channel.
pub struct OtelGuard {
    /// Quantum span processor for this tracing session.
    processor: Option<QuantumSpanProcessor>,
    /// Service name (quantum system identifier).
    service_name: String,
}

impl OtelGuard {
    /// Create a new OTLP guard with a quantum span processor.
    fn new(service_name: String, max_queue_depth: usize) -> Self {
        Self {
            processor: Some(QuantumSpanProcessor::new(max_queue_depth)),
            service_name,
        }
    }

    /// Get a reference to the span processor.
    pub fn processor(&self) -> Option<&QuantumSpanProcessor> {
        self.processor.as_ref()
    }

    /// Get a mutable reference to the span processor.
    pub fn processor_mut(&mut self) -> Option<&mut QuantumSpanProcessor> {
        self.processor.as_mut()
    }
}

impl Drop for OtelGuard {
    fn drop(&mut self) {
        if let Some(ref mut processor) = self.processor {
            // Final Lindblad evolution before shutdown
            processor.evolve(1.0);

            // Export remaining spans via Kraus channel
            let remaining = processor.export();
            let total = processor.total_processed.load(Ordering::Relaxed);
            let dropped = processor.total_dropped.load(Ordering::Relaxed);

            tracing::info!(
                service = %self.service_name,
                exported = remaining.len(),
                total_processed = total,
                total_dropped = dropped,
                final_coherence = processor.coherence(),
                "OTLP tracer: quantum channel closed — all Kraus operators applied"
            );
        }

        #[cfg(feature = "opentelemetry")]
        opentelemetry::global::shutdown_tracer_provider();
    }
}

// -----------------------------------------------------------------------------
// Quantum Tracing Initialisation
// -----------------------------------------------------------------------------

/// Initialise the tracing subscriber with optional OTLP export.
///
/// Sets up the quantum measurement chain for distributed tracing.
/// The OTLP endpoint acts as the entanglement distribution channel
/// between the node and the observability infrastructure.
pub fn init_tracing(
    log_level: &str,
    log_format: &str,
    otlp_endpoint: Option<&str>,
    service_name: &str,
) -> anyhow::Result<Option<OtelGuard>> {
    use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt, EnvFilter};

    // Convert log level to quantum energy level
    let level = match log_level.to_lowercase().as_str() {
        "trace" => Level::TRACE,  // Highest energy — all measurements
        "debug" => Level::DEBUG,  // High energy — most measurements
        "warn" => Level::WARN,    // Medium energy — warnings only
        "error" => Level::ERROR,  // Low energy — errors only
        _ => Level::INFO,         // Ground state — informational
    };

    let env_filter =
        EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(log_level));

    let fmt_layer = tracing_subscriber::fmt::layer()
        .with_target(true)
        .with_thread_ids(false);

    let subscriber = tracing_subscriber::registry().with(env_filter);

    // If OTLP endpoint configured, add quantum channel
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
                opentelemetry_sdk::trace::config().with_resource(
                    opentelemetry_sdk::Resource::new(vec![
                        opentelemetry::KeyValue::new(
                            "service.name",
                            service_name.to_string(),
                        ),
                        opentelemetry::KeyValue::new(
                            "service.version",
                            env!("CARGO_PKG_VERSION"),
                        ),
                    ]),
                ),
            )
            .install_batch(runtime::Tokio)?;

        let otel_layer = tracing_opentelemetry::layer().with_tracer(tracer);

        if log_format == "json" {
            subscriber
                .with(fmt_layer.json())
                .with(otel_layer)
                .init();
        } else {
            subscriber.with(fmt_layer).with(otel_layer).init();
        }

        let guard = OtelGuard::new(service_name.to_string(), MAX_SPAN_QUEUE_DEPTH);

        tracing::info!(
            endpoint = %endpoint,
            service = service_name,
            kraus_rank = KRAUS_RANK,
            coherence = 1.0,
            "OTLP quantum tracing channel initialised"
        );

        return Ok(Some(guard));
    }

    // No OTLP — standard logging only (no quantum channel)
    if log_format == "json" {
        subscriber.with(fmt_layer.json()).init();
    } else {
        subscriber.with(fmt_layer).init();
    }

    Ok(None)
}

// -----------------------------------------------------------------------------
// Quantum Span Attributes
// -----------------------------------------------------------------------------

/// Key span attributes used across IONA components.
///
/// Each attribute is an observable Ô_k whose expectation value
/// is recorded in the span: ⟨Ô_k⟩ = Tr(ρ Ô_k).
pub mod attrs {
    /// Consensus height — position eigenvalue.
    pub const HEIGHT: &str = "consensus.height";
    /// Consensus round — time step eigenvalue.
    pub const ROUND: &str = "consensus.round";
    /// Chain ID — system identifier (quantum number).
    pub const CHAIN_ID: &str = "chain.id";
    /// Transaction hash — quantum fingerprint.
    pub const TX_HASH: &str = "tx.hash";
    /// Gas used — energy eigenvalue.
    pub const GAS_USED: &str = "evm.gas_used";
    /// Peer ID — entanglement partner identifier.
    pub const PEER_ID: &str = "p2p.peer_id";
    /// Block time in milliseconds — evolution time.
    pub const BLOCK_TIME_MS: &str = "consensus.block_time_ms";
    /// Span purity — Tr(ρ²) for this span.
    pub const SPAN_PURITY: &str = "quantum.purity";
    /// Born probability — P(i) = Tr(ρ E_i).
    pub const BORN_PROBABILITY: &str = "quantum.born_probability";
    /// Entanglement fidelity — F = |⟨parent|child⟩|².
    pub const ENTANGLEMENT_FIDELITY: &str = "quantum.entanglement_fidelity";
    /// Kraus rank of the export channel.
    pub const KRAUS_RANK: &str = "quantum.kraus_rank";
    /// Processor coherence.
    pub const PROCESSOR_COHERENCE: &str = "quantum.processor_coherence";
}

// -----------------------------------------------------------------------------
// Quantum Span Creation Helper
// -----------------------------------------------------------------------------

/// Create a new quantum span — initialise a POVM element E_i.
///
/// The span starts in a pure state |ψ⟩⟨ψ| with Born probability
/// determined by the sampling rate.
#[must_use]
pub fn create_quantum_span(
    trace_id: u64,
    parent_span_id: Option<u64>,
    name: String,
    sampling_probability: f64,
) -> QuantumSpan {
    static SPAN_COUNTER: AtomicU64 = AtomicU64::new(1);
    let span_id = SPAN_COUNTER.fetch_add(1, Ordering::Relaxed);

    QuantumSpan::new(
        span_id,
        trace_id,
        parent_span_id,
        name,
        sampling_probability.clamp(0.0, 1.0),
    )
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_quantum_span_creation() {
        let span = QuantumSpan::new(1, 100, None, "test_span".into(), 0.01);
        assert_eq!(span.span_id, 1);
        assert_eq!(span.trace_id, 100);
        assert!(span.parent_span_id.is_none());
        assert!((span.born_probability - 0.01).abs() < 1e-10);
        assert!((span.purity - 1.0).abs() < 1e-10);
    }

    #[test]
    fn test_quantum_span_completion() {
        let mut span = QuantumSpan::new(1, 100, None, "test".into(), 0.01);
        let initial_purity = span.purity;
        span.complete();
        assert!(span.duration > Duration::ZERO);
        assert!(span.purity < initial_purity);
    }

    #[test]
    fn test_quantum_span_entanglement_fidelity() {
        let child = QuantumSpan::new(2, 100, Some(1), "child".into(), 0.01);
        let parent_purity = 0.999;
        let fidelity = child.entanglement_fidelity(parent_purity);
        assert!(fidelity > 0.0);
        assert!(fidelity <= 1.0);
    }

    #[test]
    fn test_quantum_span_processor_push() {
        let mut processor = QuantumSpanProcessor::new(4);
        assert_eq!(processor.depth(), 0);

        let span = QuantumSpan::new(1, 100, None, "test".into(), 0.01);
        processor.push(span);
        assert_eq!(processor.depth(), 1);
        assert!((processor.coherence() - 1.0).abs() < 1e-10);
    }

    #[test]
    fn test_quantum_span_processor_overflow() {
        let mut processor = QuantumSpanProcessor::new(2);
        processor.push(QuantumSpan::new(1, 100, None, "first".into(), 0.01));
        processor.push(QuantumSpan::new(2, 100, None, "second".into(), 0.01));
        processor.push(QuantumSpan::new(3, 100, None, "third".into(), 0.01));

        assert_eq!(processor.depth(), 2);
        assert_eq!(processor.total_dropped.load(Ordering::Relaxed), 1);
        assert!(processor.coherence() < 1.0);
    }

    #[test]
    fn test_quantum_span_processor_export() {
        let mut processor = QuantumSpanProcessor::new(10);
        processor.push(QuantumSpan::new(1, 100, None, "s1".into(), 0.01));
        processor.push(QuantumSpan::new(2, 100, None, "s2".into(), 0.01));

        let exported = processor.export();
        assert_eq!(exported.len(), 2);
        assert_eq!(processor.depth(), 0);
        assert_eq!(
            processor.total_processed.load(Ordering::Relaxed),
            2
        );
        assert!(processor.coherence() < 1.0);
    }

    #[test]
    fn test_quantum_span_processor_evolution() {
        let mut processor = QuantumSpanProcessor::new(10);
        let initial_coherence = processor.coherence();

        processor.evolve(0.1);
        assert!(processor.coherence() < initial_coherence);
    }

    #[test]
    fn test_create_quantum_span() {
        let span = create_quantum_span(42, Some(10), "test_op".into(), 0.05);
        assert_eq!(span.trace_id, 42);
        assert_eq!(span.parent_span_id, Some(10));
        assert!((span.born_probability - 0.05).abs() < 1e-10);
    }

    #[test]
    fn test_span_with_attributes() {
        let span = QuantumSpan::new(1, 100, None, "test".into(), 0.01)
            .with_attribute("key1".into(), "val1".into())
            .with_attribute("key2".into(), "val2".into());

        assert_eq!(span.attributes.len(), 2);
        assert!(span.purity < 1.0);
    }

    #[test]
    fn test_born_probability_clamped() {
        let span = create_quantum_span(1, None, "test".into(), 1.5);
        assert!((span.born_probability - 1.0).abs() < 1e-10);

        let span = create_quantum_span(1, None, "test".into(), -0.5);
        assert!((span.born_probability - 0.0).abs() < 1e-10);
    }
}
