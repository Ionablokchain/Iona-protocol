/// API-key middleware — axum 0.7 compatible.
///
/// axum 0.7 removed the generic `B` type parameter from `Request<B>` and
/// `Next<B>`. Middleware now takes `Request` (= `Request<Body>`) and `Next`
/// with no type parameters.
use axum::{
    body::Body,
    extract::State,
    http::{Request, StatusCode},
    middleware::Next,
    response::Response,
};
use std::sync::Arc;

/// Configuration for the API key middleware.
#[derive(Clone, Debug)]
pub struct ApiKeyConfig {
    pub header: String,
    pub value: String,
}

impl ApiKeyConfig {
    pub fn new(header: impl Into<String>, value: impl Into<String>) -> Self {
        Self {
            header: header.into(),
            value: value.into(),
        }
    }
}

/// axum 0.7 middleware: rejects requests without a valid API key.
/// Wire with: `middleware::from_fn_with_state(Arc::new(cfg), require_api_key)`
pub async fn require_api_key(
    State(cfg): State<Arc<ApiKeyConfig>>,
    req: Request<Body>,
    next: Next,
) -> Result<Response, StatusCode> {
    let ok = req
        .headers()
        .get(&cfg.header)
        .and_then(|v| v.to_str().ok())
        .map(|v| v == cfg.value)
        .unwrap_or(false);
    if ok {
        Ok(next.run(req).await)
    } else {
        Err(StatusCode::UNAUTHORIZED)
    }
}

/// Convenience: checks Bearer token in Authorization header.
pub async fn require_bearer(
    State(cfg): State<Arc<ApiKeyConfig>>,
    req: Request<Body>,
    next: Next,
) -> Result<Response, StatusCode> {
    let ok = req
        .headers()
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .map(|token| token == cfg.value)
        .unwrap_or(false);
    if ok {
        Ok(next.run(req).await)
    } else {
        Err(StatusCode::UNAUTHORIZED)
    }
}
