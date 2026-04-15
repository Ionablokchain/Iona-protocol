//! API‑key middleware — axum 0.7 compatible.
//!
//! Provides middleware to protect routes with a static API key (via custom header)
//! or Bearer token (Authorization: Bearer <token>).
//!
//! # Example
//!
//! ```rust,ignore
//! use axum::Router;
//! use std::sync::Arc;
//! use iona::rpc::auth_api_key::{ApiKeyConfig, require_api_key};
//!
//! let config = Arc::new(ApiKeyConfig::new("x-api-key", "secret123"));
//! let app = Router::new()
//!     .route("/admin", get(admin_handler))
//!     .layer(axum::middleware::from_fn_with_state(config, require_api_key));
//! ```
//!
//! axum 0.7 removed the generic `B` type parameter from `Request<B>` and
//! `Next<B>`. Middleware now takes `Request` (= `Request<Body>`) and `Next`
//! with no type parameters.

use axum::{
    body::Body,
    extract::State,
    http::{Request, StatusCode},
    middleware::Next,
    response::Response,
};
use std::sync::Arc;
use tracing::{debug, warn};

/// Configuration for the API key middleware.
#[derive(Clone, Debug)]
pub struct ApiKeyConfig {
    /// Name of the HTTP header that carries the API key.
    pub header: String,
    /// The expected API key value.
    pub value: String,
}

impl ApiKeyConfig {
    /// Create a new configuration with the given header name and key value.
    pub fn new(header: impl Into<String>, value: impl Into<String>) -> Self {
        Self {
            header: header.into(),
            value: value.into(),
        }
    }
}

/// axum 0.7 middleware: rejects requests without a valid API key.
///
/// The API key is expected in a custom header (configured in `ApiKeyConfig`).
/// If the header is missing or the value does not match, returns `401 Unauthorized`.
///
/// # Usage
///
/// ```rust,ignore
/// .layer(axum::middleware::from_fn_with_state(Arc::new(config), require_api_key))
/// ```
pub async fn require_api_key(
    State(cfg): State<Arc<ApiKeyConfig>>,
    req: Request<Body>,
    next: Next,
) -> Result<Response, StatusCode> {
    let header_value = req
        .headers()
        .get(&cfg.header)
        .and_then(|v| v.to_str().ok());

    let ok = header_value.map(|v| v == cfg.value).unwrap_or(false);

    if ok {
        debug!("API key authentication succeeded");
        Ok(next.run(req).await)
    } else {
        warn!(
            header = %cfg.header,
            provided = ?header_value,
            "API key authentication failed"
        );
        Err(StatusCode::UNAUTHORIZED)
    }
}

/// Convenience middleware that checks a Bearer token in the `Authorization` header.
///
/// The expected token is configured in `ApiKeyConfig.value` (the header name is ignored).
/// The request must contain `Authorization: Bearer <token>`.
///
/// # Usage
///
/// ```rust,ignore
/// .layer(axum::middleware::from_fn_with_state(Arc::new(config), require_bearer))
/// ```
pub async fn require_bearer(
    State(cfg): State<Arc<ApiKeyConfig>>,
    req: Request<Body>,
    next: Next,
) -> Result<Response, StatusCode> {
    let token = req
        .headers()
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .map(|t| t.trim());

    let ok = token.map(|t| t == cfg.value).unwrap_or(false);

    if ok {
        debug!("Bearer token authentication succeeded");
        Ok(next.run(req).await)
    } else {
        warn!(
            provided = ?token,
            "Bearer token authentication failed"
        );
        Err(StatusCode::UNAUTHORIZED)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{
        routing::get,
        Router,
    };
    use http::{Request, StatusCode};
    use std::sync::Arc;
    use tower::ServiceExt;

    async fn dummy_handler() -> &'static str {
        "ok"
    }

    fn test_app(config: Arc<ApiKeyConfig>, use_bearer: bool) -> Router {
        let middleware = if use_bearer {
            axum::middleware::from_fn_with_state(config.clone(), require_bearer)
        } else {
            axum::middleware::from_fn_with_state(config.clone(), require_api_key)
        };
        Router::new()
            .route("/protected", get(dummy_handler))
            .layer(middleware)
    }

    #[tokio::test]
    async fn test_api_key_valid() {
        let config = Arc::new(ApiKeyConfig::new("x-api-key", "secret"));
        let app = test_app(config, false);

        let req = Request::builder()
            .uri("/protected")
            .header("x-api-key", "secret")
            .body(Body::empty())
            .unwrap();

        let res = app.oneshot(req).await.unwrap();
        assert_eq!(res.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_api_key_invalid() {
        let config = Arc::new(ApiKeyConfig::new("x-api-key", "secret"));
        let app = test_app(config, false);

        let req = Request::builder()
            .uri("/protected")
            .header("x-api-key", "wrong")
            .body(Body::empty())
            .unwrap();

        let res = app.oneshot(req).await.unwrap();
        assert_eq!(res.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn test_api_key_missing() {
        let config = Arc::new(ApiKeyConfig::new("x-api-key", "secret"));
        let app = test_app(config, false);

        let req = Request::builder()
            .uri("/protected")
            .body(Body::empty())
            .unwrap();

        let res = app.oneshot(req).await.unwrap();
        assert_eq!(res.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn test_bearer_valid() {
        let config = Arc::new(ApiKeyConfig::new("", "secret"));
        let app = test_app(config, true);

        let req = Request::builder()
            .uri("/protected")
            .header("authorization", "Bearer secret")
            .body(Body::empty())
            .unwrap();

        let res = app.oneshot(req).await.unwrap();
        assert_eq!(res.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_bearer_invalid() {
        let config = Arc::new(ApiKeyConfig::new("", "secret"));
        let app = test_app(config, true);

        let req = Request::builder()
            .uri("/protected")
            .header("authorization", "Bearer wrong")
            .body(Body::empty())
            .unwrap();

        let res = app.oneshot(req).await.unwrap();
        assert_eq!(res.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn test_bearer_malformed() {
        let config = Arc::new(ApiKeyConfig::new("", "secret"));
        let app = test_app(config, true);

        let req = Request::builder()
            .uri("/protected")
            .header("authorization", "Basic abc")
            .body(Body::empty())
            .unwrap();

        let res = app.oneshot(req).await.unwrap();
        assert_eq!(res.status(), StatusCode::UNAUTHORIZED);
    }
}
