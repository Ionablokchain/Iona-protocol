use crate::rpc::eth_rpc::{handle_rpc, EthRpcState};
use axum::{routing::post, Router};

pub fn build_router(state: EthRpcState) -> Router {
    Router::new()
        .route("/rpc", post(handle_rpc))
        .route("/health", axum::routing::get(|| async { "ok" }))
        .with_state(state)
}
