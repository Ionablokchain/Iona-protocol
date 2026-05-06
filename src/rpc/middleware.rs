//! Axum middleware for RPC hardening.
//!
//! Layers applied (outermost → innermost):
//!   1. `request_id`      — inject X-Request-ID; add to tracing span
//!   2. `header_size`     — reject requests with oversized header blocks (8 KiB)
//!   3. `read_limit`      — rate-limit GET/HEAD requests per IP
//!   4. `concurrency`     — reject when MAX_CONCURRENT_REQUESTS is reached
//!   5. `body_limit`      — reject oversized bodies before deserialization (Content-Length)
//!   6. `json_depth`      — reject POST bodies with JSON nesting depth > MAX_JSON_DEPTH
//!
//! All middleware that needs the limiter extracts it via `Extension<Arc<RpcLimiter>>`.
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

/// Header names.
const X_REQUEST_ID_HEADER: &str = "x-request-id";
const RETRY_AFTER_HEADER: &str = "retry-after";

/// Error codes for JSON responses.
const ERR_HEADERS_TOO_LARGE: &str = "HEADERS_TOO_LARGE";
const ERR_RATE_LIMITED: &str = "RATE_LIMITED";
const ERR_OVERLOADED: &str = "OVERLOADED";
const ERR_PAYLOAD_TOO_LARGE: &str = "PAYLOAD_TOO_LARGE";
const ERR_JSON_TOO_DEEP: &str = "JSON_TOO_DEEP";

// -----------------------------------------------------------------------------
// Error type (though middleware doesn't return this directly, we define it for completeness)
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
/// Runs before the limiter is consulted to avoid per-IP state for malformed requests.
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
        return (
            StatusCode::REQUEST_HEADER_FIELDS_TOO_LARGE,
            [(X_REQUEST_ID_HEADER, req_id)],
            error_json_body(ERR_HEADERS_TOO_LARGE, "request headers exceed size limit"),
        )
            .into_response();
    }

    next.run(req).await
}

// -----------------------------------------------------------------------------
// Read rate-limit middleware
// -----------------------------------------------------------------------------

/// Middleware that applies `check_read()` to every GET/HEAD request.
/// POST requests are rate-limited separately via `check_submit()` inside each handler.
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
                    return (
                        StatusCode::TOO_MANY_REQUESTS,
                        [
                            (X_REQUEST_ID_HEADER, req_id),
                            (RETRY_AFTER_HEADER, "1"),
                        ],
                        error_json_body(ERR_RATE_LIMITED, "read rate limit exceeded"),
                    )
                        .into_response();
                }
            }
        }
    }

    next.run(req).await
}

// -----------------------------------------------------------------------------
// Global concurrency cap middleware
// -----------------------------------------------------------------------------

/// Middleware that enforces the global concurrent-request cap.
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
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                [
                    (X_REQUEST_ID_HEADER, req_id),
                    (RETRY_AFTER_HEADER, "1"),
                ],
                error_json_body(ERR_OVERLOADED, "server at capacity"),
            )
                .into_response();
        }
    };

    next.run(req).await
}

// -----------------------------------------------------------------------------
// Body-size guard middleware
// -----------------------------------------------------------------------------

/// Middleware that enforces MAX_BODY_BYTES via the Content-Length header (cheap check).
/// If the body is oversized, returns 413 with a structured error.
/// Actual streaming bodies are bounded by the json_depth_middleware below.
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
            return (
                StatusCode::PAYLOAD_TOO_LARGE,
                [(X_REQUEST_ID_HEADER, req_id)],
                error_json_body(ERR_PAYLOAD_TOO_LARGE, "request body exceeds limit"),
            )
                .into_response();
        }
    }

    next.run(req).await
}

// -----------------------------------------------------------------------------
// JSON nesting-depth guard middleware
// -----------------------------------------------------------------------------

/// Middleware that collects the request body (bounded by MAX_BODY_BYTES + 1)
/// and rejects it if the JSON nesting depth exceeds MAX_JSON_DEPTH.
/// The body is re-assembled and passed to the next handler unchanged.
///
/// Only applied to requests with `Content-Type: application/json` bodies (POST/PUT/PATCH).
pub async fn json_depth_middleware(req: Request, next: Next) -> Response {
    let is_json_post = {
        let method_ok = matches!(req.method(), &Method::POST | &Method::PUT | &Method::PATCH);
        let ct_ok = req
            .headers()
            .get(header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .map(|ct| ct.contains("application/json"))
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
            return (
                StatusCode::PAYLOAD_TOO_LARGE,
                [(X_REQUEST_ID_HEADER, req_id)],
                error_json_body(ERR_PAYLOAD_TOO_LARGE, "body collection failed or too large"),
            )
                .into_response();
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
        return (
            StatusCode::UNPROCESSABLE_ENTITY,
            [(X_REQUEST_ID_HEADER, req_id)],
            error_json_body(ERR_JSON_TOO_DEEP, "JSON nesting depth exceeds limit"),
        )
            .into_response();
    }

    let req = Request::from_parts(parts, Body::from(bytes));
    next.run(req).await
}

// -----------------------------------------------------------------------------
// JSON depth calculation
// -----------------------------------------------------------------------------

/// Count the maximum JSON nesting depth of a byte slice without full parsing.
/// Strings are skipped (including escaped braces/brackets inside them).
/// Returns 0 for empty or non-JSON input.
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
// Helpers
// -----------------------------------------------------------------------------

/// Build a structured, opaque error response with no internal details.
pub fn error_response(status: StatusCode, code: &str, req_id: &str) -> Response {
    let body = format!(
        r#"{{"error":{{"code":"{code}","request_id":"{req_id}"}}}}"#,
        code = code,
        req_id = req_id
    );
    (
        status,
        [
            (header::CONTENT_TYPE, "application/json"),
            (X_REQUEST_ID_HEADER, req_id),
        ],
        body,
    )
        .into_response()
}

/// Helper to create JSON error body string.
fn error_json_body(code: &str, message: &str) -> String {
    format!(
        r#"{{"error":{{"code":"{}","message":"{}"}}}}"#,
        code, message
    )
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_json_nesting_depth() {
        let shallow = br#"{"a":1}"#;
        assert_eq!(json_nesting_depth(shallow), 1);

        let deep = br#"{"a":{"b":{"c":{"d":1}}}}"#;
        assert_eq!(json_nesting_depth(deep), 4);

        let array = br#"[[[1]]]"#;
        assert_eq!(json_nesting_depth(array), 3);

        let mix = br#"{"a":[1,2,{"b":3}]}"#;
        assert_eq!(json_nesting_depth(mix), 3);

        let escaped = br#"{"a":"{\"b\":1}"}"#;
        assert_eq!(json_nesting_depth(escaped), 1);

        let empty = b"";
        assert_eq!(json_nesting_depth(empty), 0);

        let not_json = b"hello";
        assert_eq!(json_nesting_depth(not_json), 0);
    }
}
