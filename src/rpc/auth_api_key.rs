use axum::{
    http::{Request, StatusCode},
    middleware::Next,
    response::Response,
};
use std::sync::Arc;

#[derive(Clone)]
pub struct ApiKeyConfig {
    pub header: String,
    pub value: String,
}

impl ApiKeyConfig {
    pub fn new(header: impl Into<String>, value: impl Into<String>) -> Self {
        Self { header: header.into(), value: value.into() }
    }
}

/// ULTRA: API key middleware template.
/// Wire this into router layers for write endpoints only.
pub async fn require_api_key<B>(
    cfg: Arc<ApiKeyConfig>,
    req: Request<B>,
    next: Next<B>,
) -> Result<Response, StatusCode> {
    let header_name = cfg.header.as_str();
    match req.headers().get(header_name).and_then(|v| v.to_str().ok()) {
        Some(v) if v == cfg.value => Ok(next.run(req).await),
        _ => Err(StatusCode::UNAUTHORIZED),
    }
}
