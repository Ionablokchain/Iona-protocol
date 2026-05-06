//! RPC module — core Ethereum‑compatible JSON‑RPC server and supporting types.
//!
//! This module contains all components needed to serve an Ethereum‑style JSON‑RPC API
//! for the IONA blockchain. It includes:
//!
//! - `eth_rpc` – main request handler and state
//! - `router` – Axum router setup
//! - `middleware` – hardening middleware (rate‑limiting, body limits, JSON depth)
//! - `txpool` – transaction pool logic
//! - `fs_store` – state persistence (snapshots, EVM accounts)
//! - `admin_auth`, `rbac` – administrative authentication and role‑based access
//! - Supporting utilities: `basefee`, `bloom`, `eth_header`, `eth_rlp`, `mpt`, `proofs`, `state_trie`, `tx_decode`, `withdrawals`, `block_store`, `chain_store`, `cert_reload`, `auth_api_key`
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
// Re‑exports of commonly used types
// -----------------------------------------------------------------------------

pub use eth_rpc::{Block, EthRpcState, JsonRpcReq, JsonRpcResp, Log, Receipt, TxRecord};
pub use router::serve as serve_rpc;
pub use txpool::{PendingTx, TxPool};
pub use fs_store::{save_snapshot, load_snapshot, snapshot_from_state, apply_snapshot_to_state, maybe_persist, save_head, load_head, persist_evm_accounts, load_evm_accounts};
pub use middleware::{RpcLimiter, new_request_id, RpcLimitResult, MAX_BODY_BYTES, MAX_CONCURRENT_REQUESTS};
pub use admin_auth::AdminAuthLayer;
pub use rbac::Rbac;
pub use auth_api_key::ApiKeyAuth;

// -----------------------------------------------------------------------------
// Prelude
// -----------------------------------------------------------------------------

/// Convenience prelude for the RPC module.
pub mod prelude {
    pub use super::{
        EthRpcState,
        JsonRpcReq,
        JsonRpcResp,
        Receipt,
        Log,
        Block,
        TxPool,
        PendingTx,
        RpcLimiter,
        serve_rpc,
    };
}
