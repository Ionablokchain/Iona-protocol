//! Axum middleware for RPC hardening.
//!
//! Layers applied (outermost → innermost, i.e. first to last in request flow):
//!   1. `request_id`      — inject X-Request-ID; add to tracing span
//!   2. `header_size`     — reject requests with oversized header blocks (8 KiB)
//!   3. `read_limit`      — rate-limit GET/HEAD requests per IP
//!   4. `concurrency`     — reject when MAX_CONCURRENT_REQUESTS is reached
//!   5. `body_limit`      — reject oversized bodies before deserialization (Content-Length)
//!   6. `json_depth`      — reject POST bodies with JSON nesting depth > MAX_JSON_DEPTH
//!
//! All middleware that needs the limiter extracts it via
//! `axum::extract::Extension<Arc<RpcLimiter>>`, which is inserted by
//! `.layer(Extension(limiter.clone()))` placed outer to these middleware.
//!
//! Router setup (iona-node.rs):
//! ```ignore
//! let router = Router::new()
//!     /* … routes … */
//!     .with_state(app.clone())
//!     .layer(middleware::from_fn(json_depth_middleware))
//!     .layer(middleware::from_fn(body_limit_middleware))
//!     .layer(middleware::from_fn(concurrency_middleware))
//!     .layer(middleware::from_fn(read_limit_middleware))
//!     .layer(Extension(app.limiter.clone()))
//!     .layer(middleware::from_fn(header_size_middleware))
//!     .layer(middleware::from_fn(request_id_middleware))
//!     .layer(CorsLayer::…);
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

use crate::rpc_limits::{new_request_id, RpcLimitResult, RpcLimiter, MAX_BODY_BYTES};

/// Maximum total byte size of all request headers combined (8 KiB).
pub const MAX_HEADER_BYTES: usize = 8_192;

/// Maximum JSON object/array nesting depth accepted in POST bodies.
pub const MAX_JSON_DEPTH: usize = 32;

// ── X-Request-ID middleware ────────────────────────────────────────────────

/// Middleware that injects a unique `X-Request-ID` into every request/response.
/// Also creates a tracing span so all log lines inside the handler carry the ID.
pub async fn request_id_middleware(mut req: Request, next: Next) -> Response {
    let req_id = new_request_id();
    req.headers_mut().insert(
        "x-request-id",
        HeaderValue::from_str(&req_id).unwrap_or_else(|_| HeaderValue::from_static("bad-id")),
    );

    let span = tracing::info_span!("rpc_request", req_id = %req_id);
    let _guard = span.enter();

    let mut response = next.run(req).await;

    // Echo the request-ID back in the response so clients can correlate.
    response.headers_mut().insert(
        "x-request-id",
        HeaderValue::from_str(&req_id).unwrap_or_else(|_| HeaderValue::from_static("bad-id")),
    );

    response
}

// ── Header-size guard middleware ──────────────────────────────────────────

/// Middleware that rejects requests whose combined header block exceeds MAX_HEADER_BYTES.
/// Runs before the limiter is consulted to avoid per-IP state for malformed requests.
pub async fn header_size_middleware(req: Request, next: Next) -> Response {
    let total: usize = req
        .headers()
        .iter()
        .map(|(k, v)| k.as_str().len() + v.len() + 4) // name + ": " + value + "\r\n"
        .sum();

    if total > MAX_HEADER_BYTES {
        let req_id = req
            .headers()
            .get("x-request-id")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("unknown")
            .to_string();
        tracing::warn!(%req_id, header_bytes = total, max = MAX_HEADER_BYTES,
            "rpc::middleware: header block too large");
        return (
            StatusCode::REQUEST_HEADER_FIELDS_TOO_LARGE,
            [("x-request-id", req_id.as_str())],
            r#"{"error":{"code":"HEADERS_TOO_LARGE","message":"request headers exceed size limit"}}"#,
        )
            .into_response();
    }

    next.run(req).await
}

// ── Read rate-limit middleware ─────────────────────────────────────────────

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
            .get("x-request-id")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("unknown")
            .to_string();

        // Extract IP injected by axum's ConnectInfo extension.
        if let Some(ci) = req
            .extensions()
            .get::<axum::extract::ConnectInfo<std::net::SocketAddr>>()
        {
            let ip = ci.0.ip();
            match limiter.check_read(ip, &req_id) {
                RpcLimitResult::Allowed => {}
                _ => {
                    tracing::warn!(%req_id, %ip, "rpc::middleware: read rate limit exceeded");
                    return (
                        StatusCode::TOO_MANY_REQUESTS,
                        [("x-request-id", req_id.as_str()), ("retry-after", "1")],
                        r#"{"error":{"code":"RATE_LIMITED","message":"read rate limit exceeded"}}"#,
                    )
                        .into_response();
                }
            }
        }
    }

    next.run(req).await
}

// ── Global concurrency cap middleware ─────────────────────────────────────

/// Middleware that enforces the global concurrent-request cap.
/// Returns HTTP 503 when the cap is reached.
pub async fn concurrency_middleware(
    limiter: axum::extract::Extension<Arc<RpcLimiter>>,
    req: Request,
    next: Next,
) -> Response {
    let req_id = req
        .headers()
        .get("x-request-id")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("unknown")
        .to_string();

    let _ticket = match limiter.try_concurrency_slot(&req_id) {
        Some(t) => t,
        None => {
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                [("x-request-id", req_id.as_str()), ("retry-after", "1")],
                r#"{"error":{"code":"OVERLOADED","message":"server at capacity"}}"#,
            )
                .into_response();
        }
    };

    next.run(req).await
}

// ── Body-size guard middleware ────────────────────────────────────────────

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
        .get("x-request-id")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("unknown")
        .to_string();

    // Check Content-Length header first (cheap).
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
                %req_id,
                content_length = cl,
                max = MAX_BODY_BYTES,
                "rpc::middleware: body too large (content-length check)"
            );
            return (
                StatusCode::PAYLOAD_TOO_LARGE,
                [("x-request-id", req_id.as_str())],
                r#"{"error":{"code":"PAYLOAD_TOO_LARGE","message":"request body exceeds limit"}}"#,
            )
                .into_response();
        }
    }

    next.run(req).await
}

// ── JSON nesting-depth guard middleware ───────────────────────────────────

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
        .get("x-request-id")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("unknown")
        .to_string();

    // Collect body (bounded: MAX_BODY_BYTES + 1 so we detect over-limit here too).
    let (parts, body) = req.into_parts();
    let bytes: Bytes = match axum::body::to_bytes(body, MAX_BODY_BYTES + 1).await {
        Ok(b) => b,
        Err(_) => {
            return (
                StatusCode::PAYLOAD_TOO_LARGE,
                [("x-request-id", req_id.as_str())],
                r#"{"error":{"code":"PAYLOAD_TOO_LARGE","message":"body collection failed or too large"}}"#,
            )
                .into_response();
        }
    };

    let depth = json_nesting_depth(&bytes);
    if depth > MAX_JSON_DEPTH {
        tracing::warn!(
            %req_id,
            json_depth = depth,
            max = MAX_JSON_DEPTH,
            "rpc::middleware: JSON nesting depth exceeded"
        );
        return (
            StatusCode::UNPROCESSABLE_ENTITY,
            [("x-request-id", req_id.as_str())],
            r#"{"error":{"code":"JSON_TOO_DEEP","message":"JSON nesting depth exceeds limit"}}"#,
        )
            .into_response();
    }

    // Re-assemble request with collected body.
    let req = Request::from_parts(parts, Body::from(bytes));
    next.run(req).await
}

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
                    if depth > max_depth {
                        max_depth = depth;
                    }
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

// ── Safe error response helper ────────────────────────────────────────────

/// Build a structured, opaque error response with no internal details.
pub fn error_response(status: StatusCode, code: &str, req_id: &str) -> Response {
    let body = format!(r#"{{"error":{{"code":"{code}","request_id":"{req_id}"}}}}"#);
    (
        status,
        [
            ("content-type", "application/json"),
            ("x-request-id", req_id),
        ],
        body,
    )
        .into_response()
}
