//! RPC module — Quantum Ethereum‑compatible JSON‑RPC server.
//!
//! # Quantum RPC Architecture
//!
//! The RPC server is modelled as a **quantum observable** Ô_rpc that
//! measures the state of the blockchain and returns eigenvalues to clients.
//! Each request is a **projective measurement** collapsing the node's
//! quantum state to a classical JSON response.
//!
//! # Mathematical Formalism
//!
//! ## RPC as Quantum Measurement
//! ```text
//! Ô_rpc = Σ_i λ_i |method_i⟩⟨method_i|
//! ⟨Ô_rpc⟩ = Tr(ρ_node Ô_rpc)
//! ```
//!
//! ## Hamiltonian for RPC Operations
//! ```text
//! Ĥ_rpc = Ĥ_query + Ĥ_submit + Ĥ_admin
//!
//! Ĥ_query  = Σ_q ω_q a†_q a_q              (read request oscillators)
//! Ĥ_submit = Σ_s g_s b†_s b_s              (write request oscillators)
//! Ĥ_admin  = Σ_a E_a |admin_a⟩⟨admin_a|    (administrative eigenstates)
//! ```
//!
//! ## Request-Response as Quantum Channel
//! ```text
//! Φ_rpc(ρ) = Σ_k K_k ρ K_k†
//! K_k = √p_k |response_k⟩⟨request_k|
//! ```
//!
//! # Submodules
//!
//! - `eth_rpc` – main request handler and quantum state
//! - `router` – Axum router with quantum channel setup
//! - `middleware` – hardening via quantum rate limiting
//! - `txpool` – transaction pool (quantum harmonic oscillator)
//! - `fs_store` – quantum state persistence
//! - `admin_auth`, `rbac` – quantum access control
//!
//! # Example
//!
//! ```rust,ignore
//! use iona::rpc::{EthRpcState, router::serve, middleware::RpcLimiter};
//!
//! let state = EthRpcState::default();
//! let limiter = RpcLimiter::new();
//! let app = router::create_router(state, limiter);
//! axum::Server::bind(&addr).serve(app.into_make_service()).await?;
//! ```

pub mod admin_auth;
pub mod auth_api_key;
pub mod basefee;
pub mod block_store;
pub mod bloom;
pub mod cert_reload;
pub mod chain_store;
pub mod eth_header;
pub mod eth_rlp;
pub mod eth_rpc;
pub mod fs_store;
pub mod middleware;
pub mod mpt;
pub mod proofs;
pub mod rbac;
pub mod rlp_encode;
pub mod router;
pub mod state_trie;
pub mod tx_decode;
pub mod txpool;
pub mod withdrawals;

// -----------------------------------------------------------------------------
// Quantum Constants
// -----------------------------------------------------------------------------

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

// -----------------------------------------------------------------------------
// Quantum RPC State
// -----------------------------------------------------------------------------

/// Quantum state of the RPC server.
///
/// Tracks the density matrix properties of the request-response system,
/// providing observables for monitoring server health.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct QuantumRpcState {
    /// Purity γ = Tr(ρ²) of the RPC state.
    pub purity: f64,
    /// Von Neumann entropy S = -Tr(ρ ln ρ).
    pub entropy: f64,
    /// Coherence of the request handling.
    pub request_coherence: f64,
    /// Entanglement fidelity with the node state.
    pub node_entanglement: f64,
    /// Total requests served (cumulative measurements).
    pub total_requests: u64,
    /// Total successful responses.
    pub total_successes: u64,
    /// Total error responses (decoherence events).
    pub total_errors: u64,
    /// Whether the RPC server is healthy.
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
    /// Create a new quantum RPC state in the ground state |∅⟩.
    pub fn new() -> Self {
        Self::default()
    }

    /// Record a successful request — measurement with high fidelity.
    pub fn record_success(&mut self) {
        self.total_requests = self.total_requests.wrapping_add(1);
        self.total_successes = self.total_successes.wrapping_add(1);
        let decay = (-RPC_DECOHERENCE_RATE).exp();
        self.request_coherence = (self.request_coherence * decay).clamp(0.0, 1.0);
        self.recompute();
    }

    /// Record an error response — measurement with decoherence.
    pub fn record_error(&mut self) {
        self.total_requests = self.total_requests.wrapping_add(1);
        self.total_errors = self.total_errors.wrapping_add(1);
        let decay = (-RPC_DECOHERENCE_RATE * 10.0).exp();
        self.request_coherence = (self.request_coherence * decay).clamp(0.0, 1.0);
        self.recompute();
    }

    /// Apply the Kraus channel for a general RPC operation.
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

// -----------------------------------------------------------------------------
// Re‑exports of commonly used types
// -----------------------------------------------------------------------------

pub use eth_rpc::{Block, EthRpcState, JsonRpcReq, JsonRpcResp, Log, Receipt, TxRecord};
pub use router::serve as serve_rpc;
pub use txpool::{PendingTx, TxPool};
pub use fs_store::{
    apply_snapshot_to_state, load_evm_accounts, load_head, load_snapshot, maybe_persist,
    persist_evm_accounts, save_head, save_snapshot, snapshot_from_state,
};
pub use middleware::{
    new_request_id, RpcLimitResult, RpcLimiter, MAX_BODY_BYTES, MAX_CONCURRENT_REQUESTS,
};
pub use admin_auth::AdminAuthLayer;
pub use rbac::Rbac;
pub use auth_api_key::ApiKeyAuth;

// -----------------------------------------------------------------------------
// Prelude
// -----------------------------------------------------------------------------

/// Convenience prelude for the RPC module.
pub mod prelude {
    pub use super::{
        Block, EthRpcState, JsonRpcReq, JsonRpcResp, Log, PendingTx, Receipt, RpcLimiter, TxPool,
        serve_rpc, QuantumRpcState,
    };
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

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
    fn test_health_check() {
        let mut state = QuantumRpcState::new();
        assert!(state.is_healthy);

        // Many errors cause health degradation
        for _ in 0..10000 {
            state.record_error();
        }
        assert!(!state.is_healthy);
    }

    #[test]
    fn test_purity_never_negative() {
        let mut state = QuantumRpcState::new();
        for _ in 0..100000 {
            state.record_error();
        }
        assert!(state.purity >= 0.0);
    }
}
