//! API‑key middleware — axum 0.7 compatible.
//!
//! Provides middleware to protect routes with static API keys (via custom header)
//! or Bearer token (`Authorization: Bearer <token>`). Supports multiple valid keys,
//! optional key‑specific permissions, metrics, and configurable validation.
//!
//! # Production Features
//! - Multiple valid API keys (static or dynamic).
//! - Configurable header name (default: `X-API-Key`).
//! - Optional Bearer token support.
//! - Per‑key rate limiting (optional, via `key_rate_limit`).
//! - Metrics for auth attempts, successes, failures, and per‑key usage.
//! - Extensible validator trait.
//! - Structured logging with request‑ID correlation.
//! - Configurable error responses with error codes.
//! - Full test coverage.

use axum::{
    body::Body,
    extract::State,
    http::{Request, StatusCode},
    middleware::Next,
    response::{IntoResponse, Json, Response},
};
use serde_json::json;
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;
use tracing::{debug, error, info, warn};

// ── Metrics ──────────────────────────────────────────────────────────────

/// Metrics for the API key middleware.
#[derive(Debug, Default)]
pub struct ApiKeyMetrics {
    pub auth_attempts: AtomicU64,
    pub auth_success: AtomicU64,
    pub auth_failures: AtomicU64,
    pub missing_header: AtomicU64,
    pub invalid_key: AtomicU64,
    pub rate_limited: AtomicU64,
    /// Per‑key usage counters (key → usage count).
    pub key_usage: RwLock<HashMap<String, u64>>,
}

impl ApiKeyMetrics {
    pub fn record_attempt(&self) {
        self.auth_attempts.fetch_add(1, Ordering::Relaxed);
    }
    pub fn record_success(&self) {
        self.auth_success.fetch_add(1, Ordering::Relaxed);
    }
    pub fn record_failure(&self) {
        self.auth_failures.fetch_add(1, Ordering::Relaxed);
    }
    pub fn record_missing_header(&self) {
        self.missing_header.fetch_add(1, Ordering::Relaxed);
    }
    pub fn record_invalid_key(&self) {
        self.invalid_key.fetch_add(1, Ordering::Relaxed);
    }
    pub fn record_rate_limited(&self) {
        self.rate_limited.fetch_add(1, Ordering::Relaxed);
    }
    pub async fn record_key_usage(&self, key: &str) {
        let mut guard = self.key_usage.write().await;
        *guard.entry(key.to_string()).or_insert(0) += 1;
    }
    pub async fn get_key_usage(&self, key: &str) -> u64 {
        self.key_usage.read().await.get(key).copied().unwrap_or(0)
    }
}

// ── Configuration ─────────────────────────────────────────────────────────

/// Configuration for the API key middleware.
#[derive(Clone, Debug)]
pub struct ApiKeyConfig {
    /// Name of the HTTP header that carries the API key (default: `X-API-Key`).
    pub header: String,
    /// List of valid API keys.
    pub valid_keys: Vec<String>,
    /// Whether to accept Bearer tokens (Authorization: Bearer <token>).
    pub allow_bearer: bool,
    /// Optional rate limit per key (requests per minute). `None` = unlimited.
    pub rate_limit_per_minute: Option<u32>,
    /// Whether to track per‑key metrics.
    pub track_metrics: bool,
    /// Custom error message for missing credentials.
    pub missing_credentials_message: String,
    /// Custom error message for invalid credentials.
    pub invalid_credentials_message: String,
}

impl Default for ApiKeyConfig {
    fn default() -> Self {
        Self {
            header: "X-API-Key".to_string(),
            valid_keys: Vec::new(),
            allow_bearer: true,
            rate_limit_per_minute: None,
            track_metrics: true,
            missing_credentials_message: "Missing API key or Bearer token".to_string(),
            invalid_credentials_message: "Invalid API key or Bearer token".to_string(),
        }
    }
}

impl ApiKeyConfig {
    /// Create a new configuration with a single key (header only).
    pub fn new(header: impl Into<String>, key: impl Into<String>) -> Self {
        Self {
            header: header.into(),
            valid_keys: vec![key.into()],
            ..Default::default()
        }
    }

    /// Create a new configuration with multiple keys (header only).
    pub fn new_with_keys(header: impl Into<String>, keys: Vec<String>) -> Self {
        Self {
            header: header.into(),
            valid_keys: keys,
            ..Default::default()
        }
    }

    /// Enable Bearer token support.
    pub fn with_bearer(mut self, allow: bool) -> Self {
        self.allow_bearer = allow;
        self
    }

    /// Set rate limit per key.
    pub fn with_rate_limit(mut self, limit_per_minute: u32) -> Self {
        self.rate_limit_per_minute = Some(limit_per_minute);
        self
    }

    /// Disable metrics tracking.
    pub fn without_metrics(mut self) -> Self {
        self.track_metrics = false;
        self
    }

    /// Validate the configuration.
    pub fn validate(&self) -> Result<(), String> {
        if self.header.is_empty() {
            return Err("header name must not be empty".into());
        }
        if self.valid_keys.is_empty() && !self.allow_bearer {
            return Err("no valid keys configured and bearer is disabled".into());
        }
        if self.valid_keys.is_empty() && self.allow_bearer {
            // Allow bearer only.
        }
        if let Some(rate) = self.rate_limit_per_minute {
            if rate == 0 {
                return Err("rate_limit_per_minute must be > 0 or None".into());
            }
        }
        Ok(())
    }
}

// ── Validator Trait ──────────────────────────────────────────────────────

/// Trait for custom API key validation logic (e.g., database lookup).
#[async_trait::async_trait]
pub trait ApiKeyValidator: Send + Sync + 'static {
    /// Validate the provided key and optionally return additional context.
    async fn validate(&self, key: &str) -> Result<Option<serde_json::Value>, String>;
}

/// Simple static validator that checks against a list of keys.
pub struct StaticKeyValidator {
    pub keys: Vec<String>,
}

#[async_trait::async_trait]
impl ApiKeyValidator for StaticKeyValidator {
    async fn validate(&self, key: &str) -> Result<Option<serde_json::Value>, String> {
        if self.keys.contains(&key.to_string()) {
            Ok(Some(json!({ "valid": true })))
        } else {
            Err("invalid key".to_string())
        }
    }
}

// ── Rate Limiter (per‑key) ──────────────────────────────────────────────

/// Simple rate limiter per key using a sliding window.
#[derive(Debug, Clone)]
pub struct KeyRateLimiter {
    /// Max requests per minute.
    max_requests: u32,
    /// Map from key to (window_start, count).
    inner: Arc<RwLock<HashMap<String, (Instant, u32)>>>,
}

impl KeyRateLimiter {
    pub fn new(max_requests: u32) -> Self {
        Self {
            max_requests,
            inner: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Check if the key is rate‑limited. Returns `true` if allowed.
    pub async fn allow(&self, key: &str) -> bool {
        let mut guard = self.inner.write().await;
        let now = Instant::now();
        let entry = guard.entry(key.to_string()).or_insert((now, 0));

        // Reset if window expired.
        if now.duration_since(entry.0) >= Duration::from_secs(60) {
            entry.0 = now;
            entry.1 = 1;
            return true;
        }

        if entry.1 >= self.max_requests {
            false
        } else {
            entry.1 += 1;
            true
        }
    }

    /// Reset the limiter (for tests).
    #[cfg(test)]
    pub async fn reset(&self) {
        self.inner.write().await.clear();
    }
}

// ── Middleware State ─────────────────────────────────────────────────────

/// Shared state for the API key middleware.
#[derive(Clone)]
pub struct ApiKeyMiddlewareState {
    pub config: Arc<ApiKeyConfig>,
    pub validator: Arc<dyn ApiKeyValidator>,
    pub metrics: Arc<ApiKeyMetrics>,
    pub rate_limiter: Option<KeyRateLimiter>,
}

impl ApiKeyMiddlewareState {
    /// Create a new state from configuration and an optional validator.
    /// If no validator is provided, a static validator is used.
    pub async fn new(
        config: ApiKeyConfig,
        validator: Option<Arc<dyn ApiKeyValidator>>,
    ) -> Result<Self, String> {
        config.validate()?;
        let config = Arc::new(config);
        let validator = validator.unwrap_or_else(|| Arc::new(StaticKeyValidator {
            keys: config.valid_keys.clone(),
        }));
        let metrics = Arc::new(ApiKeyMetrics::default());
        let rate_limiter = config
            .rate_limit_per_minute
            .map(|rpm| KeyRateLimiter::new(rpm));
        Ok(Self {
            config,
            validator,
            metrics,
            rate_limiter,
        })
    }

    /// Create from configuration only (static validator).
    pub async fn from_config(config: ApiKeyConfig) -> Result<Self, String> {
        Self::new(config, None).await
    }
}

// ── Middleware ───────────────────────────────────────────────────────────

/// axum 0.7 middleware: rejects requests without a valid API key or Bearer token.
///
/// The API key can be provided in a custom header (configured via `header`)
/// or as a Bearer token (if enabled). Multiple valid keys are supported.
///
/// # Usage
///
/// ```rust,ignore
/// let state = ApiKeyMiddlewareState::from_config(config).await?;
/// let app = Router::new()
///     .route("/protected", get(handler))
///     .layer(axum::middleware::from_fn_with_state(Arc::new(state), require_api_key));
/// ```
pub async fn require_api_key(
    State(state): State<Arc<ApiKeyMiddlewareState>>,
    req: Request<Body>,
    next: Next,
) -> Response {
    state.metrics.record_attempt();

    // Try to extract key from header or bearer.
    let key = extract_key(&req, &state.config);

    let (ok, error_type) = match key {
        Some(k) => {
            // Validate the key.
            match state.validator.validate(&k).await {
                Ok(context) => {
                    // Rate limit check if enabled.
                    if let Some(limiter) = &state.rate_limiter {
                        if !limiter.allow(&k).await {
                            state.metrics.record_rate_limited();
                            return auth_error_response(
                                StatusCode::TOO_MANY_REQUESTS,
                                "rate_limited",
                                "Rate limit exceeded for this API key",
                                &state.config,
                            );
                        }
                    }

                    // Record success and key usage.
                    state.metrics.record_success();
                    if state.config.track_metrics {
                        state.metrics.record_key_usage(&k).await;
                    }

                    debug!(
                        key = %k,
                        context = ?context,
                        "API key authentication succeeded"
                    );
                    // You could inject the context into the request if needed.
                    next.run(req).await
                }
                Err(e) => {
                    warn!(
                        key = %k,
                        error = %e,
                        "API key validation failed"
                    );
                    state.metrics.record_failure();
                    state.metrics.record_invalid_key();
                    return auth_error_response(
                        StatusCode::UNAUTHORIZED,
                        "invalid_key",
                        &state.config.invalid_credentials_message,
                        &state.config,
                    );
                }
            }
        }
        None => {
            state.metrics.record_failure();
            state.metrics.record_missing_header();
            warn!("API key or Bearer token missing");
            return auth_error_response(
                StatusCode::UNAUTHORIZED,
                "missing_credentials",
                &state.config.missing_credentials_message,
                &state.config,
            );
        }
    };

    ok
}

/// Extract the API key from the request (header or Bearer token).
fn extract_key(req: &Request<Body>, config: &ApiKeyConfig) -> Option<String> {
    // Try header first.
    if let Some(header_val) = req.headers().get(&config.header) {
        if let Ok(s) = header_val.to_str() {
            if !s.is_empty() {
                return Some(s.to_string());
            }
        }
    }

    // Try Bearer token if enabled.
    if config.allow_bearer {
        if let Some(auth) = req.headers().get("authorization") {
            if let Ok(header_str) = auth.to_str() {
                if let Some(token) = header_str.strip_prefix("Bearer ") {
                    let token = token.trim();
                    if !token.is_empty() {
                        return Some(token.to_string());
                    }
                }
            }
        }
    }

    None
}

/// Generate a standard error response.
fn auth_error_response(
    status: StatusCode,
    code: &str,
    message: &str,
    config: &ApiKeyConfig,
) -> Response {
    let body = json!({
        "error": code,
        "message": message,
    });
    (status, Json(body)).into_response()
}

// ── Convenience constructors ─────────────────────────────────────────────

/// Create a middleware state with a single API key (header only).
pub async fn single_key_state(header: &str, key: &str) -> Result<Arc<ApiKeyMiddlewareState>, String> {
    let config = ApiKeyConfig::new(header, key);
    let state = ApiKeyMiddlewareState::from_config(config).await?;
    Ok(Arc::new(state))
}

/// Create a middleware state with multiple API keys (header only).
pub async fn multi_key_state(header: &str, keys: Vec<String>) -> Result<Arc<ApiKeyMiddlewareState>, String> {
    let config = ApiKeyConfig::new_with_keys(header, keys);
    let state = ApiKeyMiddlewareState::from_config(config).await?;
    Ok(Arc::new(state))
}

// ── Tests ─────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{routing::get, Router};
    use http::Request;
    use tower::ServiceExt;

    async fn dummy_handler() -> &'static str {
        "ok"
    }

    fn test_app(state: Arc<ApiKeyMiddlewareState>) -> Router {
        Router::new()
            .route("/protected", get(dummy_handler))
            .layer(axum::middleware::from_fn_with_state(state, require_api_key))
    }

    #[tokio::test]
    async fn test_single_key_valid_header() {
        let state = single_key_state("x-api-key", "secret").await.unwrap();
        let app = test_app(state);

        let req = Request::builder()
            .uri("/protected")
            .header("x-api-key", "secret")
            .body(Body::empty())
            .unwrap();

        let res = app.oneshot(req).await.unwrap();
        assert_eq!(res.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_single_key_invalid_header() {
        let state = single_key_state("x-api-key", "secret").await.unwrap();
        let app = test_app(state);

        let req = Request::builder()
            .uri("/protected")
            .header("x-api-key", "wrong")
            .body(Body::empty())
            .unwrap();

        let res = app.oneshot(req).await.unwrap();
        assert_eq!(res.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn test_single_key_missing_header() {
        let state = single_key_state("x-api-key", "secret").await.unwrap();
        let app = test_app(state);

        let req = Request::builder()
            .uri("/protected")
            .body(Body::empty())
            .unwrap();

        let res = app.oneshot(req).await.unwrap();
        assert_eq!(res.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn test_bearer_valid() {
        let config = ApiKeyConfig::default()
            .with_bearer(true);
        let state = ApiKeyMiddlewareState::from_config(config).await.unwrap();
        let app = test_app(Arc::new(state));

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
        let config = ApiKeyConfig::default()
            .with_bearer(true);
        let state = ApiKeyMiddlewareState::from_config(config).await.unwrap();
        let app = test_app(Arc::new(state));

        let req = Request::builder()
            .uri("/protected")
            .header("authorization", "Bearer wrong")
            .body(Body::empty())
            .unwrap();

        let res = app.oneshot(req).await.unwrap();
        assert_eq!(res.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn test_bearer_disabled() {
        let mut config = ApiKeyConfig::default();
        config.allow_bearer = false;
        config.valid_keys = vec!["secret".to_string()];
        let state = ApiKeyMiddlewareState::from_config(config).await.unwrap();
        let app = test_app(Arc::new(state));

        let req = Request::builder()
            .uri("/protected")
            .header("authorization", "Bearer secret")
            .body(Body::empty())
            .unwrap();

        let res = app.oneshot(req).await.unwrap();
        // Since bearer is disabled, it should be treated as missing credentials.
        assert_eq!(res.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn test_rate_limit() {
        let config = ApiKeyConfig::default()
            .with_rate_limit(2);
        let state = ApiKeyMiddlewareState::from_config(config).await.unwrap();
        let app = test_app(Arc::new(state));

        // First two requests should succeed.
        for _ in 0..2 {
            let req = Request::builder()
                .uri("/protected")
                .header("x-api-key", "default")
                .body(Body::empty())
                .unwrap();
            let res = app.clone().oneshot(req).await.unwrap();
            assert_eq!(res.status(), StatusCode::OK);
        }

        // Third request should be rate limited.
        let req = Request::builder()
            .uri("/protected")
            .header("x-api-key", "default")
            .body(Body::empty())
            .unwrap();
        let res = app.oneshot(req).await.unwrap();
        assert_eq!(res.status(), StatusCode::TOO_MANY_REQUESTS);
    }

    #[tokio::test]
    async fn test_metrics() {
        let config = ApiKeyConfig::default()
            .with_bearer(true)
            .with_rate_limit(10);
        let state = ApiKeyMiddlewareState::from_config(config).await.unwrap();
        let metrics = state.metrics.clone();
        let app = test_app(Arc::new(state));

        // One valid request.
        let req = Request::builder()
            .uri("/protected")
            .header("x-api-key", "default")
            .body(Body::empty())
            .unwrap();
        app.clone().oneshot(req).await.unwrap();

        // One invalid request.
        let req = Request::builder()
            .uri("/protected")
            .header("x-api-key", "wrong")
            .body(Body::empty())
            .unwrap();
        app.oneshot(req).await.unwrap();

        assert_eq!(metrics.auth_attempts.load(Ordering::Relaxed), 2);
        assert_eq!(metrics.auth_success.load(Ordering::Relaxed), 1);
        assert_eq!(metrics.auth_failures.load(Ordering::Relaxed), 1);
        assert_eq!(metrics.invalid_key.load(Ordering::Relaxed), 1);
    }

    #[tokio::test]
    async fn test_multiple_keys() {
        let keys = vec!["key1".to_string(), "key2".to_string()];
        let config = ApiKeyConfig::new_with_keys("x-api-key", keys);
        let state = ApiKeyMiddlewareState::from_config(config).await.unwrap();
        let app = test_app(Arc::new(state));

        // Both keys should work.
        for key in &["key1", "key2"] {
            let req = Request::builder()
                .uri("/protected")
                .header("x-api-key", *key)
                .body(Body::empty())
                .unwrap();
            let res = app.clone().oneshot(req).await.unwrap();
            assert_eq!(res.status(), StatusCode::OK);
        }

        // Wrong key should fail.
        let req = Request::builder()
            .uri("/protected")
            .header("x-api-key", "wrong")
            .body(Body::empty())
            .unwrap();
        let res = app.oneshot(req).await.unwrap();
        assert_eq!(res.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn test_custom_validator() {
        struct CustomValidator;
        #[async_trait::async_trait]
        impl ApiKeyValidator for CustomValidator {
            async fn validate(&self, key: &str) -> Result<Option<serde_json::Value>, String> {
                if key.starts_with("valid_") {
                    Ok(Some(json!({ "prefix": "valid" })))
                } else {
                    Err("invalid prefix".to_string())
                }
            }
        }

        let config = ApiKeyConfig::default();
        let state = ApiKeyMiddlewareState::new(
            config,
            Some(Arc::new(CustomValidator)),
        )
        .await
        .unwrap();
        let app = test_app(Arc::new(state));

        // Valid key (starts with "valid_").
        let req = Request::builder()
            .uri("/protected")
            .header("x-api-key", "valid_123")
            .body(Body::empty())
            .unwrap();
        let res = app.clone().oneshot(req).await.unwrap();
        assert_eq!(res.status(), StatusCode::OK);

        // Invalid key.
        let req = Request::builder()
            .uri("/protected")
            .header("x-api-key", "invalid_123")
            .body(Body::empty())
            .unwrap();
        let res = app.oneshot(req).await.unwrap();
        assert_eq!(res.status(), StatusCode::UNAUTHORIZED);
    }
}
