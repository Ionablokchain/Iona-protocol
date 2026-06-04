//! Axum router for the IONA JSON‑RPC server — Quantum Architecture.
//!
//! # Quantum Router Model
//!
//! The Axum router is modelled as a **quantum channel multiplexer** that
//! routes incoming requests to the appropriate handler subspace. Each
//! route corresponds to a distinct **quantum observable** that measures
//! a specific aspect of the node's state.
//!
//! # Mathematical Formalism
//!
//! ## Router as Quantum Demultiplexer
//! ```text
//! Ô_router = Ô_rpc + Ô_health
//!
//! Ô_rpc    = Σ_i λ_i |method_i⟩⟨method_i|
//! Ô_health = E_health |healthy⟩⟨healthy|
//! ```
//!
//! ## Hamiltonian for Routing
//! ```text
//! Ĥ_router = Ĥ_route + Ĥ_middleware + Ĥ_state
//!
//! Ĥ_route      = Σ_r ω_r a†_r a_r                     (request oscillators per route)
//! Ĥ_middleware = Σ_m g_m (|pass⟩⟨block|_m + h.c.)     (filter coupling)
//! Ĥ_state      = Σ_s E_s |state_s⟩⟨state_s|           (application state)
//! ```
//!
//! ## Request Processing as Quantum Channel
//! ```text
//! Φ_router(ρ) = Σ_k K_k ρ K_k†
//! K_k = √p_k |response_k⟩⟨request_k|
//! ```

use crate::rpc::eth_rpc::{handle_rpc, EthRpcState};
use axum::{
    extract::Request,
    middleware::Next,
    response::Response,
    routing::{get, post},
    Router,
};
use std::sync::{
    atomic::{AtomicU64, Ordering},
    Arc,
};
use thiserror::Error;

// -----------------------------------------------------------------------------
// Quantum Constants
// -----------------------------------------------------------------------------

/// Reduced Planck constant (natural units).
const HBAR: f64 = 1.0;

/// Default quantum coherence for the router.
const DEFAULT_ROUTER_COHERENCE: f64 = 1.0;

/// Decoherence rate per request.
const REQUEST_DECOHERENCE_RATE: f64 = 0.00001;

/// Minimum coherence threshold for healthy router.
const MIN_ROUTER_COHERENCE: f64 = 0.9;

/// Kraus rank for router quantum channels.
const ROUTER_KRAUS_RANK: usize = 4;

/// Path for the JSON‑RPC endpoint.
pub const RPC_PATH: &str = "/rpc";

/// Path for the health check endpoint.
pub const HEALTH_PATH: &str = "/health";

/// Health check response body.
pub const HEALTH_RESPONSE: &str = "ok";

// -----------------------------------------------------------------------------
// Quantum Router State
// -----------------------------------------------------------------------------

/// Quantum state of the Axum router.
///
/// Tracks the density matrix properties of the request routing system,
/// providing observables for monitoring router health and performance.
#[derive(Debug, Clone)]
pub struct QuantumRouterState {
    /// Purity γ = Tr(ρ²) of the router state.
    pub purity: f64,
    /// Von Neumann entropy S = -Tr(ρ ln ρ).
    pub entropy: f64,
    /// Coherence of the routing subsystem.
    pub routing_coherence: f64,
    /// Entanglement fidelity with the application state.
    pub state_entanglement: f64,
    /// Total requests processed.
    pub total_requests: AtomicU64,
    /// Total successful responses.
    pub total_successes: AtomicU64,
    /// Total error responses.
    pub total_errors: AtomicU64,
    /// Whether the router is in a healthy quantum state.
    pub is_healthy: bool,
}

impl Default for QuantumRouterState {
    fn default() -> Self {
        Self {
            purity: DEFAULT_ROUTER_COHERENCE,
            entropy: 0.0,
            routing_coherence: DEFAULT_ROUTER_COHERENCE,
            state_entanglement: DEFAULT_ROUTER_COHERENCE,
            total_requests: AtomicU64::new(0),
            total_successes: AtomicU64::new(0),
            total_errors: AtomicU64::new(0),
            is_healthy: true,
        }
    }
}

impl QuantumRouterState {
    /// Create a new quantum router state in the ground state |∅⟩.
    pub fn new() -> Self {
        Self::default()
    }

    /// Record a successful request — measurement with high fidelity.
    pub fn record_success(&mut self) {
        self.total_requests.fetch_add(1, Ordering::Relaxed);
        self.total_successes.fetch_add(1, Ordering::Relaxed);
        let decay = (-REQUEST_DECOHERENCE_RATE).exp();
        self.routing_coherence = (self.routing_coherence * decay).clamp(0.0, 1.0);
        self.recompute();
    }

    /// Record an error response — measurement with decoherence.
    pub fn record_error(&mut self) {
        self.total_requests.fetch_add(1, Ordering::Relaxed);
        self.total_errors.fetch_add(1, Ordering::Relaxed);
        let decay = (-REQUEST_DECOHERENCE_RATE * 10.0).exp();
        self.routing_coherence = (self.routing_coherence * decay).clamp(0.0, 1.0);
        self.recompute();
    }

    /// Apply the Kraus channel for a routing operation.
    pub fn apply_router_channel(&mut self) {
        let kraus_factor = (1.0 / ROUTER_KRAUS_RANK as f64).sqrt();
        self.state_entanglement = (self.state_entanglement * kraus_factor).clamp(0.0, 1.0);
        self.recompute();
    }

    fn recompute(&mut self) {
        self.purity = (self.routing_coherence * self.state_entanglement).clamp(0.0, 1.0);
        self.entropy = if self.purity >= 1.0 {
            0.0
        } else {
            -self.purity * self.purity.ln().max(0.0)
        };
        self.is_healthy = self.purity >= MIN_ROUTER_COHERENCE;
    }

    /// Get total requests (snapshot).
    pub fn total_requests(&self) -> u64 {
        self.total_requests.load(Ordering::Relaxed)
    }

    /// Get total successes (snapshot).
    pub fn total_successes(&self) -> u64 {
        self.total_successes.load(Ordering::Relaxed)
    }

    /// Get total errors (snapshot).
    pub fn total_errors(&self) -> u64 {
        self.total_errors.load(Ordering::Relaxed)
    }

    /// Get router statistics.
    pub fn stats(&self) -> RouterStats {
        RouterStats {
            purity: self.purity,
            entropy: self.entropy,
            routing_coherence: self.routing_coherence,
            state_entanglement: self.state_entanglement,
            total_requests: self.total_requests(),
            total_successes: self.total_successes(),
            total_errors: self.total_errors(),
            is_healthy: self.is_healthy,
        }
    }
}

// -----------------------------------------------------------------------------
// Router Statistics
// -----------------------------------------------------------------------------

/// Observable statistics for the quantum router.
#[derive(Debug, Clone)]
pub struct RouterStats {
    pub purity: f64,
    pub entropy: f64,
    pub routing_coherence: f64,
    pub state_entanglement: f64,
    pub total_requests: u64,
    pub total_successes: u64,
    pub total_errors: u64,
    pub is_healthy: bool,
}

// -----------------------------------------------------------------------------
// Shared Quantum State
// -----------------------------------------------------------------------------

/// Wrapper for the quantum router state to be used as Axum state.
pub type SharedQuantumRouterState = Arc<std::sync::Mutex<QuantumRouterState>>;

/// Create a new shared quantum router state.
pub fn new_shared_quantum_state() -> SharedQuantumRouterState {
    Arc::new(std::sync::Mutex::new(QuantumRouterState::new()))
}

// -----------------------------------------------------------------------------
// Quantum Tracking Middleware
// -----------------------------------------------------------------------------

/// Middleware that tracks request outcomes in the quantum router state.
///
/// This middleware wraps the handler and records success/error based on
/// the HTTP status code of the response.
pub async fn quantum_tracking_middleware(
    axum::extract::Extension(qstate): axum::extract::Extension<SharedQuantumRouterState>,
    req: Request,
    next: Next,
) -> Response {
    let response = next.run(req).await;

    if let Ok(mut state) = qstate.lock() {
        if response.status().is_success() {
            state.record_success();
        } else if response.status().is_server_error() {
            state.record_error();
        }
        state.apply_router_channel();
    }

    response
}

// -----------------------------------------------------------------------------
// Errors
// -----------------------------------------------------------------------------

/// Possible errors when building the router.
#[derive(Debug, Error)]
pub enum RouterError {
    #[error("state missing or invalid")]
    InvalidState,

    #[error("quantum decoherence: router coherence {coherence} below threshold {threshold}")]
    Decoherence {
        coherence: f64,
        threshold: f64,
    },
}

pub type RouterResult<T> = Result<T, RouterError>;

// -----------------------------------------------------------------------------
// Builder
// -----------------------------------------------------------------------------

/// Builder for creating an Axum router with optional customisations.
///
/// Supports custom paths, quantum state tracking, and middleware.
#[derive(Default)]
pub struct RouterBuilder {
    rpc_path: Option<String>,
    health_path: Option<String>,
    quantum_state: Option<SharedQuantumRouterState>,
    enable_quantum_tracking: bool,
}

impl RouterBuilder {
    /// Create a new builder with default paths.
    pub fn new() -> Self {
        Self::default()
    }

    /// Set a custom RPC path.
    pub fn with_rpc_path(mut self, path: impl Into<String>) -> Self {
        self.rpc_path = Some(path.into());
        self
    }

    /// Set a custom health check path.
    pub fn with_health_path(mut self, path: impl Into<String>) -> Self {
        self.health_path = Some(path.into());
        self
    }

    /// Enable quantum state tracking with the given shared state.
    pub fn with_quantum_state(mut self, state: SharedQuantumRouterState) -> Self {
        self.quantum_state = Some(state);
        self
    }

    /// Enable quantum tracking middleware.
    pub fn with_quantum_tracking(mut self, enable: bool) -> Self {
        self.enable_quantum_tracking = enable;
        self
    }

    /// Build the router with the given application state.
    pub fn build(self, state: EthRpcState) -> Router {
        let rpc_path = self.rpc_path.as_deref().unwrap_or(RPC_PATH);
        let health_path = self.health_path.as_deref().unwrap_or(HEALTH_PATH);

        let mut router = Router::new()
            .route(rpc_path, post(handle_rpc))
            .route(health_path, get(|| async { HEALTH_RESPONSE }))
            .with_state(state);

        // Attach quantum state if provided
        if let Some(qstate) = self.quantum_state {
            router = router.layer(axum::extract::Extension(qstate));
        }

        // Attach quantum tracking middleware if enabled
        if self.enable_quantum_tracking {
            router = router.layer(axum::middleware::from_fn(quantum_tracking_middleware));
        }

        router
    }
}

// -----------------------------------------------------------------------------
// Original function (kept for backward compatibility)
// -----------------------------------------------------------------------------

/// Create a router with the default RPC and health endpoints.
///
/// # Example
/// ```
/// use iona::rpc::eth_rpc::EthRpcState;
/// use iona::rpc::router::build_router;
///
/// let state = EthRpcState::default();
/// let app = build_router(state);
/// ```
pub fn build_router(state: EthRpcState) -> Router {
    RouterBuilder::new().build(state)
}

/// Create a router with quantum state tracking enabled.
///
/// # Example
/// ```
/// use iona::rpc::eth_rpc::EthRpcState;
/// use iona::rpc::router::{build_router_with_quantum_tracking, new_shared_quantum_state};
///
/// let state = EthRpcState::default();
/// let qstate = new_shared_quantum_state();
/// let app = build_router_with_quantum_tracking(state, qstate);
/// ```
pub fn build_router_with_quantum_tracking(
    state: EthRpcState,
    quantum_state: SharedQuantumRouterState,
) -> Router {
    RouterBuilder::new()
        .with_quantum_state(quantum_state)
        .with_quantum_tracking(true)
        .build(state)
}

// -----------------------------------------------------------------------------
// Compatibility alias for `serve`
// -----------------------------------------------------------------------------

/// Serve the RPC router on the given address.
///
/// This is a placeholder for the actual serve function. In production,
/// this would bind to a TCP listener and serve the router.
pub async fn serve(
    addr: std::net::SocketAddr,
    state: EthRpcState,
    _shutdown_rx: tokio::sync::watch::Receiver<()>,
) -> RouterResult<()> {
    let app = build_router(state);
    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .map_err(|e| RouterError::InvalidState)?;

    axum::serve(listener, app)
        .await
        .map_err(|e| RouterError::InvalidState)?;

    Ok(())
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::StatusCode;
    use tower::ServiceExt;

    // ── Classical Tests ──────────────────────────────────────────────
    #[tokio::test]
    async fn test_health_check() {
        let state = EthRpcState::default();
        let app = build_router(state);
        let response = app
            .oneshot(
                axum::http::Request::builder()
                    .uri(HEALTH_PATH)
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        assert_eq!(&body[..], HEALTH_RESPONSE.as_bytes());
    }

    #[test]
    fn test_builder_custom_paths() {
        let state = EthRpcState::default();
        let _router = RouterBuilder::new()
            .with_rpc_path("/custom-rpc")
            .with_health_path("/live")
            .build(state);
    }

    // ── Quantum Tests ────────────────────────────────────────────────
    #[test]
    fn test_quantum_router_state_initialization() {
        let state = QuantumRouterState::new();
        assert!((state.purity - 1.0).abs() < 1e-10);
        assert!((state.entropy - 0.0).abs() < 1e-10);
        assert!(state.is_healthy);
    }

    #[test]
    fn test_record_success_decoheres() {
        let mut state = QuantumRouterState::new();
        let initial_purity = state.purity;

        state.record_success();
        assert!(state.purity < initial_purity);
        assert_eq!(state.total_requests(), 1);
        assert_eq!(state.total_successes(), 1);
    }

    #[test]
    fn test_record_error_stronger_decoherence() {
        let mut state1 = QuantumRouterState::new();
        let mut state2 = QuantumRouterState::new();

        state1.record_success();
        state2.record_error();

        assert!(state2.purity < state1.purity);
        assert_eq!(state2.total_errors(), 1);
    }

    #[test]
    fn test_apply_router_channel() {
        let mut state = QuantumRouterState::new();
        let initial_entanglement = state.state_entanglement;

        state.apply_router_channel();
        assert!(state.state_entanglement < initial_entanglement);
    }

    #[test]
    fn test_health_check_purity() {
        let mut state = QuantumRouterState::new();
        assert!(state.is_healthy);

        // Many errors cause health degradation
        for _ in 0..10000 {
            state.record_error();
        }
        assert!(!state.is_healthy);
    }

    #[test]
    fn test_router_stats() {
        let mut state = QuantumRouterState::new();
        state.record_success();
        state.record_success();
        state.record_error();

        let stats = state.stats();
        assert_eq!(stats.total_requests, 3);
        assert_eq!(stats.total_successes, 2);
        assert_eq!(stats.total_errors, 1);
        assert!(stats.purity < 1.0);
    }

    #[test]
    fn test_purity_never_negative() {
        let mut state = QuantumRouterState::new();
        for _ in 0..100000 {
            state.record_error();
        }
        assert!(state.purity >= 0.0);
    }

    #[test]
    fn test_new_shared_quantum_state() {
        let shared = new_shared_quantum_state();
        let state = shared.lock().unwrap();
        assert!((state.purity - 1.0).abs() < 1e-10);
    }
}
