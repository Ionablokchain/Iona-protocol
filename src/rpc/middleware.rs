//! Axum middleware for RPC hardening — production‑grade.
//!
//! Layers applied (outermost → innermost):
//!   1. `request_id`      — inject X-Request-ID; add to tracing span
//!   2. `header_size`     — reject requests with oversized header blocks (8 KiB)
//!   3. `read_limit`      — rate‑limit GET/HEAD requests per IP
//!   4. `concurrency`     — reject when MAX_CONCURRENT_REQUESTS is reached
//!   5. `body_limit`      — reject oversized bodies before deserialization (Content-Length)
//!   6. `json_depth`      — reject POST bodies with JSON nesting depth > MAX_JSON_DEPTH
//!
//! # Example
//!
//! ```ignore
//! let router = Router::new()
//!     .route("/", post(handle_rpc))
//!     .with_state(state)
//!     .layer(middleware::from_fn(json_depth_middleware))
//!     .layer(middleware::from_fn(body_limit_middleware))
//!     .layer(middleware::from_fn(concurrency_middleware))
//!     .layer(middleware::from_fn(read_limit_middleware))
//!     .layer(Extension(limiter.clone()))
//!     .layer(middleware::from_fn(header_size_middleware))
//!     .layer(middleware::from_fn(request_id_middleware));
//! ```

use axum::{
    body::Body,
    extract::Request,
    http::{header, HeaderValue, Method, StatusCode},
    middleware::Next,
    response::{IntoResponse, Response},
};
use bytes::Bytes;
use std::sync::Arc;
use thiserror::Error;

use crate::rpc_limits::{new_request_id, RpcLimitResult, RpcLimiter, MAX_BODY_BYTES};

// -----------------------------------------------------------------------------
// Constants
// -----------------------------------------------------------------------------

/// Maximum total byte size of all request headers combined (8 KiB).
pub const MAX_HEADER_BYTES: usize = 8_192;

/// Maximum JSON object/array nesting depth accepted in POST bodies.
pub const MAX_JSON_DEPTH: usize = 32;

/// Retry-After value for rate‑limited / overloaded responses (seconds).
const RETRY_AFTER_SECONDS: &str = "1";

/// Header names.
const X_REQUEST_ID_HEADER: &str = "x-request-id";
const RETRY_AFTER_HEADER: &str = "retry-after";
const CONTENT_TYPE_JSON: &str = "application/json";

/// Error codes for JSON responses.
const ERR_HEADERS_TOO_LARGE: &str = "HEADERS_TOO_LARGE";
const ERR_RATE_LIMITED: &str = "RATE_LIMITED";
const ERR_OVERLOADED: &str = "OVERLOADED";
const ERR_PAYLOAD_TOO_LARGE: &str = "PAYLOAD_TOO_LARGE";
const ERR_JSON_TOO_DEEP: &str = "JSON_TOO_DEEP";

// -----------------------------------------------------------------------------
// Error type
// -----------------------------------------------------------------------------

/// Errors that can occur during middleware processing.
#[derive(Debug, Error)]
pub enum MiddlewareError {
    #[error("header block too large: {size} bytes (max {max})")]
    HeaderTooLarge { size: usize, max: usize },

    #[error("read rate limit exceeded for IP {ip}")]
    ReadRateLimitExceeded { ip: std::net::IpAddr },

    #[error("global concurrency limit reached")]
    ConcurrencyLimitReached,

    #[error("payload too large: {size} bytes (max {max})")]
    PayloadTooLarge { size: usize, max: usize },

    #[error("JSON nesting depth {depth} exceeds limit {max}")]
    JsonDepthExceeded { depth: usize, max: usize },
}

// -----------------------------------------------------------------------------
// Structured error response builder
// -----------------------------------------------------------------------------

/// Build a structured JSON error response with request‑ID and optional message.
fn error_response(
    status: StatusCode,
    code: &str,
    req_id: &str,
    message: &str,
) -> Response {
    let body = serde_json::json!({
        "error": {
            "code": code,
            "message": message,
            "request_id": req_id,
        }
    })
    .to_string();

    (
        status,
        [
            (header::CONTENT_TYPE, CONTENT_TYPE_JSON),
            (X_REQUEST_ID_HEADER, req_id),
        ],
        body,
    )
        .into_response()
}

// -----------------------------------------------------------------------------
// X-Request-ID middleware
// -----------------------------------------------------------------------------

/// Middleware that injects a unique `X-Request-ID` into every request/response.
/// Also creates a tracing span so all log lines inside the handler carry the ID.
pub async fn request_id_middleware(mut req: Request, next: Next) -> Response {
    let req_id = new_request_id();
    if let Ok(val) = HeaderValue::from_str(&req_id) {
        req.headers_mut().insert(X_REQUEST_ID_HEADER, val);
    }

    let span = tracing::info_span!("rpc_request", req_id = %req_id);
    let _guard = span.enter();

    let mut response = next.run(req).await;
    if let Ok(val) = HeaderValue::from_str(&req_id) {
        response.headers_mut().insert(X_REQUEST_ID_HEADER, val);
    }

    response
}

// -----------------------------------------------------------------------------
// Header-size guard middleware
// -----------------------------------------------------------------------------

/// Middleware that rejects requests whose combined header block exceeds MAX_HEADER_BYTES.
/// Runs before the limiter to avoid per‑IP state for malformed requests.
pub async fn header_size_middleware(req: Request, next: Next) -> Response {
    let total: usize = req
        .headers()
        .iter()
        .map(|(k, v)| k.as_str().len() + v.as_bytes().len() + 4) // name + ": " + value + "\r\n"
        .sum();

    if total > MAX_HEADER_BYTES {
        let req_id = req
            .headers()
            .get(X_REQUEST_ID_HEADER)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("unknown");
        tracing::warn!(
            req_id = %req_id,
            header_bytes = total,
            max = MAX_HEADER_BYTES,
            "middleware: header block too large"
        );
        return error_response(
            StatusCode::REQUEST_HEADER_FIELDS_TOO_LARGE,
            ERR_HEADERS_TOO_LARGE,
            req_id,
            "request headers exceed size limit",
        );
    }

    next.run(req).await
}

// -----------------------------------------------------------------------------
// Read rate-limit middleware
// -----------------------------------------------------------------------------

/// Middleware that applies `check_read()` to every GET/HEAD request.
/// POST requests are rate‑limited separately via `check_submit()` inside each handler.
/// If the client IP is unavailable (e.g. in tests), the request is allowed through.
pub async fn read_limit_middleware(
    limiter: axum::extract::Extension<Arc<RpcLimiter>>,
    req: Request,
    next: Next,
) -> Response {
    if req.method() == Method::GET || req.method() == Method::HEAD {
        let req_id = req
            .headers()
            .get(X_REQUEST_ID_HEADER)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("unknown");

        if let Some(ci) = req
            .extensions()
            .get::<axum::extract::ConnectInfo<std::net::SocketAddr>>()
        {
            let ip = ci.0.ip();
            match limiter.check_read(ip, req_id) {
                RpcLimitResult::Allowed => {}
                _ => {
                    tracing::warn!(
                        req_id = %req_id,
                        %ip,
                        "middleware: read rate limit exceeded"
                    );
                    return error_response(
                        StatusCode::TOO_MANY_REQUESTS,
                        ERR_RATE_LIMITED,
                        req_id,
                        "read rate limit exceeded",
                    );
                }
            }
        }
    }

    next.run(req).await
}

// -----------------------------------------------------------------------------
// Global concurrency cap middleware
// -----------------------------------------------------------------------------

/// Middleware that enforces the global concurrent‑request cap.
/// Returns HTTP 503 when the cap is reached.
pub async fn concurrency_middleware(
    limiter: axum::extract::Extension<Arc<RpcLimiter>>,
    req: Request,
    next: Next,
) -> Response {
    let req_id = req
        .headers()
        .get(X_REQUEST_ID_HEADER)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("unknown");

    let _ticket = match limiter.try_concurrency_slot(req_id) {
        Some(t) => t,
        None => {
            tracing::warn!(req_id = %req_id, "middleware: concurrency limit reached");
            return error_response(
                StatusCode::SERVICE_UNAVAILABLE,
                ERR_OVERLOADED,
                req_id,
                "server at capacity",
            );
        }
    };

    // The ticket is dropped automatically when `next.run(req).await` returns,
    // releasing the slot.
    next.run(req).await
}

// -----------------------------------------------------------------------------
// Body-size guard middleware
// -----------------------------------------------------------------------------

/// Middleware that enforces MAX_BODY_BYTES via the Content-Length header.
/// If the body is oversized, returns 413 with a structured error.
pub async fn body_limit_middleware(
    limiter: axum::extract::Extension<Arc<RpcLimiter>>,
    req: Request,
    next: Next,
) -> Response {
    let req_id = req
        .headers()
        .get(X_REQUEST_ID_HEADER)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("unknown");

    if let Some(cl) = req
        .headers()
        .get(header::CONTENT_LENGTH)
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.parse::<usize>().ok())
    {
        if cl > MAX_BODY_BYTES {
            limiter
                .metric_payload_too_large
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            tracing::warn!(
                req_id = %req_id,
                content_length = cl,
                max = MAX_BODY_BYTES,
                "middleware: body too large (content-length check)"
            );
            return error_response(
                StatusCode::PAYLOAD_TOO_LARGE,
                ERR_PAYLOAD_TOO_LARGE,
                req_id,
                "request body exceeds limit",
            );
        }
    }

    next.run(req).await
}

// -----------------------------------------------------------------------------
// JSON nesting-depth guard middleware
// -----------------------------------------------------------------------------

/// Middleware that collects the request body (bounded by MAX_BODY_BYTES + 1)
/// and rejects it if the JSON nesting depth exceeds MAX_JSON_DEPTH.
/// The body is re‑assembled and passed to the next handler unchanged.
///
/// Only applied to requests with `Content-Type: application/json` bodies (POST/PUT/PATCH).
pub async fn json_depth_middleware(req: Request, next: Next) -> Response {
    let is_json_post = {
        let method_ok = matches!(req.method(), &Method::POST | &Method::PUT | &Method::PATCH);
        let ct_ok = req
            .headers()
            .get(header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .map(|ct| ct.contains(CONTENT_TYPE_JSON))
            .unwrap_or(false);
        method_ok && ct_ok
    };

    if !is_json_post {
        return next.run(req).await;
    }

    let req_id = req
        .headers()
        .get(X_REQUEST_ID_HEADER)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("unknown");

    let (parts, body) = req.into_parts();
    let bytes: Bytes = match axum::body::to_bytes(body, MAX_BODY_BYTES + 1).await {
        Ok(b) => b,
        Err(_) => {
            return error_response(
                StatusCode::PAYLOAD_TOO_LARGE,
                ERR_PAYLOAD_TOO_LARGE,
                req_id,
                "body collection failed or too large",
            );
        }
    };

    let depth = json_nesting_depth(&bytes);
    if depth > MAX_JSON_DEPTH {
        tracing::warn!(
            req_id = %req_id,
            json_depth = depth,
            max = MAX_JSON_DEPTH,
            "middleware: JSON nesting depth exceeded"
        );
        return error_response(
            StatusCode::UNPROCESSABLE_ENTITY,
            ERR_JSON_TOO_DEEP,
            req_id,
            "JSON nesting depth exceeds limit",
        );
    }

    let req = Request::from_parts(parts, Body::from(bytes));
    next.run(req).await
}

// -----------------------------------------------------------------------------
// JSON depth calculation (robust, production‑grade)
// -----------------------------------------------------------------------------

/// Count the maximum JSON nesting depth of a byte slice without full parsing.
/// Strings are skipped (including escaped braces/brackets inside them).
/// Returns 0 for empty or non‑JSON input.
pub fn json_nesting_depth(bytes: &[u8]) -> usize {
    let mut depth: usize = 0;
    let mut max_depth: usize = 0;
    let mut in_string = false;
    let mut escape_next = false;

    for &b in bytes {
        if escape_next {
            escape_next = false;
            continue;
        }
        if in_string {
            match b {
                b'\\' => escape_next = true,
                b'"' => in_string = false,
                _ => {}
            }
        } else {
            match b {
                b'"' => in_string = true,
                b'{' | b'[' => {
                    depth += 1;
                    max_depth = max_depth.max(depth);
                }
                b'}' | b']' => {
                    depth = depth.saturating_sub(1);
                }
                _ => {}
            }
        }
    }

    max_depth
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // ── JSON depth tests ───────────────────────────────────────────────
    #[test]
    fn test_json_nesting_depth_shallow() {
        let shallow = br#"{"a":1}"#;
        assert_eq!(json_nesting_depth(shallow), 1);
    }

    #[test]
    fn test_json_nesting_depth_deep_object() {
        let deep = br#"{"a":{"b":{"c":{"d":1}}}}"#;
        assert_eq!(json_nesting_depth(deep), 4);
    }

    #[test]
    fn test_json_nesting_depth_array() {
        let array = br#"[[[1]]]"#;
        assert_eq!(json_nesting_depth(array), 3);
    }

    #[test]
    fn test_json_nesting_depth_mixed() {
        let mix = br#"{"a":[1,2,{"b":3}]}"#;
        assert_eq!(json_nesting_depth(mix), 3);
    }

    #[test]
    fn test_json_nesting_depth_escaped_quotes() {
        let escaped = br#"{"a":"{\"b\":1}"}"#;
        assert_eq!(json_nesting_depth(escaped), 1);
    }

    #[test]
    fn test_json_nesting_depth_escaped_backslash() {
        let escaped = br#"{"a":"\\"}"#;
        assert_eq!(json_nesting_depth(escaped), 1);
    }

    #[test]
    fn test_json_nesting_depth_empty() {
        assert_eq!(json_nesting_depth(b""), 0);
    }

    #[test]
    fn test_json_nesting_depth_not_json() {
        assert_eq!(json_nesting_depth(b"hello"), 0);
    }

    #[test]
    fn test_json_nesting_depth_nested_arrays() {
        let nested = br#"[1, [2, [3, [4]]]]"#;
        assert_eq!(json_nesting_depth(nested), 4);
    }

    #[test]
    fn test_json_nesting_depth_unbalanced_open() {
        let unbalanced = br#"{"a":{"b":1}"#;
        // Depth goes to 2, then string ends
        assert_eq!(json_nesting_depth(unbalanced), 2);
    }

    // ── Error response tests ───────────────────────────────────────────
    #[test]
    fn test_error_response_format() {
        let resp = error_response(
            StatusCode::TOO_MANY_REQUESTS,
            ERR_RATE_LIMITED,
            "req-1",
            "rate limited",
        );
        assert_eq!(resp.status(), StatusCode::TOO_MANY_REQUESTS);
        let headers = resp.headers();
        assert_eq!(
            headers.get(X_REQUEST_ID_HEADER).unwrap(),
            "req-1"
        );
    }
}
