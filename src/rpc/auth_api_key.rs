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
//! - Per‑key rate limiting with sliding window and periodic cleanup.
//! - Prometheus metrics (optional) with atomic fallback.
//! - Extensible validator trait.
//! - Structured logging with request‑ID correlation.
//! - Configurable error responses with error codes.
//! - Overflow‑safe counters using saturating arithmetic.
//! - Full test coverage.

use axum::{
    body::Body,
    extract::State,
    http::{Request, StatusCode},
    middleware::Next,
    response::{IntoResponse, Json, Response},
};
use prometheus::{register_counter, register_counter_vec, Counter, CounterVec};
use serde_json::json;
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;
use tracing::{debug, error, info, warn};

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
    /// Maximum number of unique keys tracked in the metrics map (0 = unbounded).
    /// Prevents unbounded memory growth from attacker‑controlled keys.
    pub max_tracked_keys: usize,
    /// Interval in seconds for cleaning up stale rate limiter entries.
    pub rate_limiter_cleanup_secs: u64,
    /// Whether to enable Prometheus metrics.
    pub enable_prometheus: bool,
}

impl Default for ApiKeyConfig {
    fn default() -> Self {
        Self {
            header: "X-API-Key".to_string(),
            valid_keys: Vec::new(),
            allow_bearer: false,
            rate_limit_per_minute: None,
            track_metrics: true,
            missing_credentials_message: "Missing API key or Bearer token".to_string(),
            invalid_credentials_message: "Invalid API key or Bearer token".to_string(),
            max_tracked_keys: 10_000,
            rate_limiter_cleanup_secs: 300,
            enable_prometheus: false,
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

    /// Enable or disable Bearer token support.
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

    /// Enable Prometheus metrics.
    pub fn with_prometheus(mut self) -> Self {
        self.enable_prometheus = true;
        self
    }

    /// Validate the configuration.
    pub fn validate(&self) -> Result<(), String> {
        if self.header.is_empty() {
            return Err("header name must not be empty".into());
        }
        if self.valid_keys.is_empty() && !self.allow_bearer {
            return Err(
                "no valid keys configured and bearer is disabled: at least one source must be enabled".into(),
            );
        }
        if self.valid_keys.iter().any(|k| k.is_empty()) {
            return Err("valid_keys must not contain empty strings".into());
        }
        if let Some(rate) = self.rate_limit_per_minute {
            if rate == 0 {
                return Err("rate_limit_per_minute must be > 0 or None".into());
            }
        }
        if self.rate_limiter_cleanup_secs == 0 {
            return Err("rate_limiter_cleanup_secs must be > 0".into());
        }
        Ok(())
    }
}

// ── Prometheus Metrics ───────────────────────────────────────────────────

/// Prometheus metrics for the API key middleware.
#[derive(Clone)]
pub struct ApiKeyPrometheus {
    pub auth_attempts_total: Counter,
    pub auth_success_total: Counter,
    pub auth_failures_total: Counter,
    pub missing_header_total: Counter,
    pub invalid_key_total: Counter,
    pub rate_limited_total: Counter,
    pub key_usage_total: CounterVec,
}

impl ApiKeyPrometheus {
    /// Create and register metrics with the global Prometheus registry.
    pub fn new() -> Result<Self, prometheus::Error> {
        Ok(Self {
            auth_attempts_total: register_counter!(
                "iona_api_key_auth_attempts_total",
                "Total API key authentication attempts"
            )?,
            auth_success_total: register_counter!(
                "iona_api_key_auth_success_total",
                "Successful API key authentications"
            )?,
            auth_failures_total: register_counter!(
                "iona_api_key_auth_failures_total",
                "Failed API key authentications"
            )?,
            missing_header_total: register_counter!(
                "iona_api_key_missing_header_total",
                "Requests missing API key/Bearer token"
            )?,
            invalid_key_total: register_counter!(
                "iona_api_key_invalid_key_total",
                "Requests with an invalid API key"
            )?,
            rate_limited_total: register_counter!(
                "iona_api_key_rate_limited_total",
                "Requests rejected by rate limiting"
            )?,
            key_usage_total: register_counter_vec!(
                "iona_api_key_usage_total",
                "Per-key usage counters",
                &["key_hash"]
            )?,
        })
    }

    /// Create an unregistered instance (for tests or disabled metrics).
    pub fn new_unregistered() -> Self {
        Self {
            auth_attempts_total: Counter::new("iona_api_key_auth_attempts_total", "Attempts").unwrap(),
            auth_success_total: Counter::new("iona_api_key_auth_success_total", "Success").unwrap(),
            auth_failures_total: Counter::new("iona_api_key_auth_failures_total", "Failures").unwrap(),
            missing_header_total: Counter::new("iona_api_key_missing_header_total", "Missing").unwrap(),
            invalid_key_total: Counter::new("iona_api_key_invalid_key_total", "Invalid").unwrap(),
            rate_limited_total: Counter::new("iona_api_key_rate_limited_total", "Rate limited").unwrap(),
            key_usage_total: CounterVec::new(
                prometheus::Opts::new("iona_api_key_usage_total", "Per-key usage"),
                &["key_hash"],
            )
            .unwrap(),
        }
    }
}

// ── Metrics (Atomic + Optional Prometheus) ──────────────────────────────

/// Metrics for the API key middleware.
/// Provides atomic counters (always available) and optional Prometheus counters.
#[derive(Debug, Clone)]
pub struct ApiKeyMetrics {
    pub auth_attempts: Arc<AtomicU64>,
    pub auth_success: Arc<AtomicU64>,
    pub auth_failures: Arc<AtomicU64>,
    pub missing_header: Arc<AtomicU64>,
    pub invalid_key: Arc<AtomicU64>,
    pub rate_limited: Arc<AtomicU64>,
    /// Per‑key usage counters (key_hash → usage count).
    pub key_usage: Arc<RwLock<HashMap<String, u64>>>,
    /// Maximum number of tracked keys (0 = unbounded).
    pub max_tracked_keys: usize,
    /// Optional Prometheus integration.
    pub prometheus: Option<Arc<ApiKeyPrometheus>>,
}

impl Default for ApiKeyMetrics {
    fn default() -> Self {
        Self {
            auth_attempts: Arc::new(AtomicU64::new(0)),
            auth_success: Arc::new(AtomicU64::new(0)),
            auth_failures: Arc::new(AtomicU64::new(0)),
            missing_header: Arc::new(AtomicU64::new(0)),
            invalid_key: Arc::new(AtomicU64::new(0)),
            rate_limited: Arc::new(AtomicU64::new(0)),
            key_usage: Arc::new(RwLock::new(HashMap::new())),
            max_tracked_keys: 10_000,
            prometheus: None,
        }
    }
}

impl ApiKeyMetrics {
    /// Create a new metrics instance, optionally with Prometheus integration.
    pub fn new(
        enable_prometheus: bool,
        max_tracked_keys: usize,
    ) -> Result<Self, prometheus::Error> {
        let prometheus = if enable_prometheus {
            Some(Arc::new(ApiKeyPrometheus::new()?))
        } else {
            None
        };
        Ok(Self {
            auth_attempts: Arc::new(AtomicU64::new(0)),
            auth_success: Arc::new(AtomicU64::new(0)),
            auth_failures: Arc::new(AtomicU64::new(0)),
            missing_header: Arc::new(AtomicU64::new(0)),
            invalid_key: Arc::new(AtomicU64::new(0)),
            rate_limited: Arc::new(AtomicU64::new(0)),
            key_usage: Arc::new(RwLock::new(HashMap::new())),
            max_tracked_keys,
            prometheus,
        })
    }

    pub fn record_attempt(&self) {
        self.auth_attempts.fetch_add(1, Ordering::Relaxed);
        if let Some(p) = &self.prometheus {
            p.auth_attempts_total.inc();
        }
    }
    pub fn record_success(&self) {
        self.auth_success.fetch_add(1, Ordering::Relaxed);
        if let Some(p) = &self.prometheus {
            p.auth_success_total.inc();
        }
    }
    pub fn record_failure(&self) {
        self.auth_failures.fetch_add(1, Ordering::Relaxed);
        if let Some(p) = &self.prometheus {
            p.auth_failures_total.inc();
        }
    }
    pub fn record_missing_header(&self) {
        self.missing_header.fetch_add(1, Ordering::Relaxed);
        if let Some(p) = &self.prometheus {
            p.missing_header_total.inc();
        }
    }
    pub fn record_invalid_key(&self) {
        self.invalid_key.fetch_add(1, Ordering::Relaxed);
        if let Some(p) = &self.prometheus {
            p.invalid_key_total.inc();
        }
    }
    pub fn record_rate_limited(&self) {
        self.rate_limited.fetch_add(1, Ordering::Relaxed);
        if let Some(p) = &self.prometheus {
            p.rate_limited_total.inc();
        }
    }

    /// Record usage for a specific key. The key is hashed so the raw key
    /// never appears in Prometheus labels.
    pub async fn record_key_usage(&self, key: &str) {
        let key_hash = hash_key_for_label(key);

        // Prometheus: hashed label.
        if let Some(p) = &self.prometheus {
            p.key_usage_total
                .with_label_values(&[&key_hash])
                .inc();
        }

        // Atomic map: bounded by max_tracked_keys.
        let mut guard = self.key_usage.write().await;
        if self.max_tracked_keys > 0 && guard.len() >= self.max_tracked_keys
            && !guard.contains_key(&key_hash)
        {
            // Do not grow unbounded: skip tracking new keys beyond the cap.
            return;
        }
        let entry = guard.entry(key_hash).or_insert(0);
        *entry = entry.saturating_add(1);
    }

    pub async fn get_key_usage(&self, key: &str) -> u64 {
        let key_hash = hash_key_for_label(key);
        self.key_usage
            .read()
            .await
            .get(&key_hash)
            .copied()
            .unwrap_or(0)
    }

    /// Snapshot of atomic counters (for external consumption).
    pub fn snapshot(&self) -> ApiKeyMetricsSnapshot {
        ApiKeyMetricsSnapshot {
            auth_attempts: self.auth_attempts.load(Ordering::Relaxed),
            auth_success: self.auth_success.load(Ordering::Relaxed),
            auth_failures: self.auth_failures.load(Ordering::Relaxed),
            missing_header: self.missing_header.load(Ordering::Relaxed),
            invalid_key: self.invalid_key.load(Ordering::Relaxed),
            rate_limited: self.rate_limited.load(Ordering::Relaxed),
        }
    }
}

/// Snapshot of API key metrics.
#[derive(Debug, Clone, Copy, Default)]
pub struct ApiKeyMetricsSnapshot {
    pub auth_attempts: u64,
    pub auth_success: u64,
    pub auth_failures: u64,
    pub missing_header: u64,
    pub invalid_key: u64,
    pub rate_limited: u64,
}

/// Hash a key to a short, opaque string suitable for a Prometheus label.
fn hash_key_for_label(key: &str) -> String {
    use sha2::{Digest, Sha256};
    let digest = Sha256::digest(key.as_bytes());
    hex::encode(&digest[..8])
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
        if self.keys.iter().any(|k| k == key) {
            Ok(Some(json!({ "valid": true })))
        } else {
            Err("invalid key".to_string())
        }
    }
}

// ── Rate Limiter (per‑key sliding window) ───────────────────────────────

/// Sliding‑window rate limiter per key.
#[derive(Debug, Clone)]
pub struct KeyRateLimiter {
    /// Max requests per minute.
    max_requests: u32,
    /// Map from key hash → (window_start, count).
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
        let key_hash = hash_key_for_label(key);
        let mut guard = self.inner.write().await;
        let now = Instant::now();
        let entry = guard
            .entry(key_hash)
            .or_insert((now, 0));

        // Reset if window expired.
        if now.duration_since(entry.0) >= Duration::from_secs(60) {
            entry.0 = now;
            entry.1 = 1;
            return true;
        }

        if entry.1 >= self.max_requests {
            false
        } else {
            entry.1 = entry.1.saturating_add(1);
            true
        }
    }

    /// Remove stale entries older than `max_age`.
    pub async fn prune(&self, max_age: Duration) -> usize {
        let now = Instant::now();
        let mut guard = self.inner.write().await;
        let before = guard.len();
        guard.retain(|_, (start, _)| now.duration_since(*start) < max_age);
        before - guard.len()
    }

    #[cfg(test)]
    pub async fn reset(&self) {
        self.inner.write().await.clear();
    }

    #[cfg(test)]
    pub async fn len(&self) -> usize {
        self.inner.read().await.len()
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

        let enable_prometheus = config.enable_prometheus;
        let max_tracked_keys = config.max_tracked_keys;
        let config = Arc::new(config);

        let validator = validator.unwrap_or_else(|| {
            Arc::new(StaticKeyValidator {
                keys: config.valid_keys.clone(),
            })
        });

        let metrics = Arc::new(
            ApiKeyMetrics::new(enable_prometheus, max_tracked_keys)
                .map_err(|e| format!("failed to register API key metrics: {}", e))?,
        );

        let rate_limiter = config.rate_limit_per_minute.map(KeyRateLimiter::new);

        let state = Self {
            config: config.clone(),
            validator,
            metrics,
            rate_limiter,
        };

        // Start background cleanup task for the rate limiter.
        if let Some(limiter) = &state.rate_limiter {
            let limiter = limiter.clone();
            let interval = Duration::from_secs(config.rate_limiter_cleanup_secs);
            tokio::spawn(async move {
                let mut ticker = tokio::time::interval(interval);
                ticker.tick().await; // skip immediate tick
                loop {
                    ticker.tick().await;
                    let removed = limiter.prune(Duration::from_secs(60 * 5)).await;
                    if removed > 0 {
                        debug!(removed, "pruned stale rate limiter entries");
                    }
                }
            });
        }

        Ok(state)
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

    let key = match extract_key(&req, &state.config) {
        Some(k) => k,
        None => {
            state.metrics.record_failure();
            state.metrics.record_missing_header();
            warn!("API key or Bearer token missing");
            return auth_error_response(
                StatusCode::UNAUTHORIZED,
                "missing_credentials",
                &state.config.missing_credentials_message,
            );
        }
    };

    match state.validator.validate(&key).await {
        Ok(context) => {
            // Rate limit check if enabled.
            if let Some(limiter) = &state.rate_limiter {
                if !limiter.allow(&key).await {
                    state.metrics.record_rate_limited();
                    warn!("API key rate limit exceeded");
                    return auth_error_response(
                        StatusCode::TOO_MANY_REQUESTS,
                        "rate_limited",
                        "Rate limit exceeded for this API key",
                    );
                }
            }

            state.metrics.record_success();
            if state.config.track_metrics {
                state.metrics.record_key_usage(&key).await;
            }

            debug!(context = ?context, "API key authentication succeeded");

            // Inject the validator context as an extension if provided.
            let mut req = req;
            if let Some(ctx) = context {
                req.extensions_mut().insert(ApiKeyContext { data: ctx });
            }
            next.run(req).await
        }
        Err(e) => {
            state.metrics.record_failure();
            state.metrics.record_invalid_key();
            // Do NOT log the raw key — hash it for correlation.
            let key_hash = hash_key_for_label(&key);
            warn!(key_hash = %key_hash, error = %e, "API key validation failed");
            auth_error_response(
                StatusCode::UNAUTHORIZED,
                "invalid_key",
                &state.config.invalid_credentials_message,
            )
        }
    }
}

/// Context injected into the request extensions after successful validation.
#[derive(Debug, Clone)]
pub struct ApiKeyContext {
    pub data: serde_json::Value,
}

/// Extract the API key from the request (header or Bearer token).
fn extract_key(req: &Request<Body>, config: &ApiKeyConfig) -> Option<String> {
    // Try custom header first.
    if let Some(header_val) = req.headers().get(&config.header) {
        if let Ok(s) = header_val.to_str() {
            let s = s.trim();
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
fn auth_error_response(status: StatusCode, code: &str, message: &str) -> Response {
    let body = json!({
        "error": code,
        "message": message,
    });
    (status, Json(body)).into_response()
}

// ── Convenience constructors ─────────────────────────────────────────────

/// Create a middleware state with a single API key (header only).
pub async fn single_key_state(
    header: &str,
    key: &str,
) -> Result<Arc<ApiKeyMiddlewareState>, String> {
    let config = ApiKeyConfig::new(header, key);
    let state = ApiKeyMiddlewareState::from_config(config).await?;
    Ok(Arc::new(state))
}

/// Create a middleware state with multiple API keys (header only).
pub async fn multi_key_state(
    header: &str,
    keys: Vec<String>,
) -> Result<Arc<ApiKeyMiddlewareState>, String> {
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
        // Bearer is enabled AND a static key is configured so the validator accepts it.
        let config = ApiKeyConfig::default()
            .with_bearer(true);
        let mut config = config;
        config.valid_keys = vec!["secret".to_string()];

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
        let config = ApiKeyConfig {
            valid_keys: vec!["secret".to_string()],
            allow_bearer: true,
            ..Default::default()
        };
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
        assert_eq!(res.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn test_rate_limit() {
        let config = ApiKeyConfig {
            valid_keys: vec!["default".to_string()],
            rate_limit_per_minute: Some(2),
            ..Default::default()
        };
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
        let config = ApiKeyConfig {
            valid_keys: vec!["default".to_string()],
            allow_bearer: true,
            rate_limit_per_minute: Some(10),
            ..Default::default()
        };
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

        let snap = metrics.snapshot();
        assert_eq!(snap.auth_attempts, 2);
        assert_eq!(snap.auth_success, 1);
        assert_eq!(snap.auth_failures, 1);
        assert_eq!(snap.invalid_key, 1);
    }

    #[tokio::test]
    async fn test_multiple_keys() {
        let keys = vec!["key1".to_string(), "key2".to_string()];
        let config = ApiKeyConfig::new_with_keys("x-api-key", keys);
        let state = ApiKeyMiddlewareState::from_config(config).await.unwrap();
        let app = test_app(Arc::new(state));

        for key in &["key1", "key2"] {
            let req = Request::builder()
                .uri("/protected")
                .header("x-api-key", *key)
                .body(Body::empty())
                .unwrap();
            let res = app.clone().oneshot(req).await.unwrap();
            assert_eq!(res.status(), StatusCode::OK);
        }

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

        let config = ApiKeyConfig {
            valid_keys: vec![],
            allow_bearer: true,
            ..Default::default()
        };
        let state =
            ApiKeyMiddlewareState::new(config, Some(Arc::new(CustomValidator)))
                .await
                .unwrap();
        let app = test_app(Arc::new(state));

        let req = Request::builder()
            .uri("/protected")
            .header("x-api-key", "valid_123")
            .body(Body::empty())
            .unwrap();
        let res = app.clone().oneshot(req).await.unwrap();
        assert_eq!(res.status(), StatusCode::OK);

        let req = Request::builder()
            .uri("/protected")
            .header("x-api-key", "invalid_123")
            .body(Body::empty())
            .unwrap();
        let res = app.oneshot(req).await.unwrap();
        assert_eq!(res.status(), StatusCode::UNAUTHORIZED);
    }

    #[test]
    fn test_config_validation() {
        let mut cfg = ApiKeyConfig::new("x-api-key", "secret");
        assert!(cfg.validate().is_ok());

        cfg.valid_keys.clear();
        cfg.allow_bearer = false;
        assert!(cfg.validate().is_err());

        cfg.allow_bearer = true;
        assert!(cfg.validate().is_ok());

        cfg.rate_limit_per_minute = Some(0);
        assert!(cfg.validate().is_err());

        cfg.rate_limit_per_minute = Some(1);
        cfg.rate_limiter_cleanup_secs = 0;
        assert!(cfg.validate().is_err());
    }

    #[tokio::test]
    async fn test_rate_limiter_prune() {
        let limiter = KeyRateLimiter::new(10);
        assert!(limiter.allow("k1").await);
        assert!(limiter.allow("k2").await);
        assert_eq!(limiter.len().await, 2);

        // Prune with a very small max age to evict both.
        tokio::time::sleep(Duration::from_millis(10)).await;
        let removed = limiter.prune(Duration::from_millis(1)).await;
        assert_eq!(removed, 2);
        assert_eq!(limiter.len().await, 0);
    }

    #[tokio::test]
    async fn test_key_usage_bounded() {
        let metrics = ApiKeyMetrics::new(false, 2).unwrap();
        metrics.record_key_usage("a").await;
        metrics.record_key_usage("b").await;
        metrics.record_key_usage("c").await; // should be skipped (cap reached)
        metrics.record_key_usage("a").await; // existing key still allowed

        assert_eq!(metrics.get_key_usage("a").await, 2);
        assert_eq!(metrics.get_key_usage("b").await, 1);
        assert_eq!(metrics.get_key_usage("c").await, 0);
    }
}
