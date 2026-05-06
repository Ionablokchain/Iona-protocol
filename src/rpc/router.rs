//! Axum router for the IONA JSON‑RPC server.
//!
//! Provides a `build_router` function to create the complete router with
//! the RPC endpoint and health check.

use crate::rpc::eth_rpc::{handle_rpc, EthRpcState};
use axum::{routing::get, routing::post, Router};
use thiserror::Error;

// -----------------------------------------------------------------------------
// Constants
// -----------------------------------------------------------------------------

/// Path for the JSON‑RPC endpoint.
pub const RPC_PATH: &str = "/rpc";

/// Path for the health check endpoint.
pub const HEALTH_PATH: &str = "/health";

/// Health check response body.
pub const HEALTH_RESPONSE: &str = "ok";

// -----------------------------------------------------------------------------
// Errors (for builder, though current build_router doesn't fail)
// -----------------------------------------------------------------------------

/// Possible errors when building the router.
#[derive(Debug, Error)]
pub enum RouterError {
    #[error("state missing or invalid")]
    InvalidState,
}

pub type RouterResult<T> = Result<T, RouterError>;

// -----------------------------------------------------------------------------
// Builder (for future extensions)
// -----------------------------------------------------------------------------

/// Builder for creating an Axum router with optional customisations.
#[derive(Default)]
pub struct RouterBuilder {
    rpc_path: Option<String>,
    health_path: Option<String>,
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

    /// Build the router with the given state.
    pub fn build(self, state: EthRpcState) -> Router {
        let rpc_path = self.rpc_path.as_deref().unwrap_or(RPC_PATH);
        let health_path = self.health_path.as_deref().unwrap_or(HEALTH_PATH);
        Router::new()
            .route(rpc_path, post(handle_rpc))
            .route(health_path, get(|| async { HEALTH_RESPONSE }))
            .with_state(state)
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

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::StatusCode;
    use tower::ServiceExt;

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
        let router = RouterBuilder::new()
            .with_rpc_path("/custom-rpc")
            .with_health_path("/live")
            .build(state);
        // Just check that it builds (no panic).
        assert!(true);
    }
}
