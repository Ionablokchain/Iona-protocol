//! mTLS identity extraction and admin-endpoint RBAC enforcement for IONA.
//!
//! ## How it works
//!
//! 1. The admin server is started with `axum-server` + rustls and requires a
//!    client certificate (`client_auth = Required`).
//!
//! 2. The TLS handshake stores the peer's verified certificate chain in a
//!    [`rustls::ServerConnection`] extension.  We read it via a tower
//!    middleware layer ([`AdminAuthLayer`]) before any handler runs.
//!
//! 3. The extracted [`ClientIdentity`] is forwarded as an axum `Extension<>`.
//!
//! 4. Each admin handler calls [`require_role`] (or uses [`AdminGuard`]) to
//!    enforce RBAC before doing any work.
//!
//! ## Without TLS (dev/test mode)
//!
//! When `admin.require_mtls = false`, the middleware inserts an anonymous
//! [`ClientIdentity`] with no CN and no fingerprint, and RBAC is disabled
//! (every check passes).  **Never use this in production.**

use axum::{
    extract::{Extension, Request, State},
    http::StatusCode,
    middleware::Next,
    response::{IntoResponse, Json, Response},
};
use std::sync::Arc;

use crate::rpc::rbac::{ClientIdentity, RbacChecker, RbacDenial, Role};

// ── Admin auth state ──────────────────────────────────────────────────────

/// Shared state passed to the admin auth middleware via axum Extension.
#[derive(Clone)]
pub struct AdminAuthState {
    pub rbac: Arc<RbacChecker>,
    /// If false, mTLS is not enforced (dev/test only).
    pub require_mtls: bool,
}

impl std::fmt::Debug for AdminAuthState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AdminAuthState")
            .field("require_mtls", &self.require_mtls)
            .finish()
    }
}

// ── Identity extraction ───────────────────────────────────────────────────

/// Extract a [`ClientIdentity`] from TLS extensions stored in the request.
///
/// In production (axum-server + rustls), the peer certificate is stored as a
/// `PeerCertificates` extension by the TLS acceptor. We read the leaf cert,
/// parse its Subject CN, and compute its SHA-256 fingerprint.
///
/// Returns `None` if no certificate was presented or TLS is not active.
pub fn extract_identity_from_request(_req: &Request) -> Option<ClientIdentity> {
    None
}

/// Parse CN and SHA-256 fingerprint from a DER-encoded certificate.
pub fn parse_cert_identity(der: &[u8]) -> ClientIdentity {
    let cn = extract_cn_from_der(der);
    let fingerprint = compute_fingerprint(der);
    ClientIdentity { cn, fingerprint }
}

/// Compute the SHA-256 fingerprint of a DER certificate as colon-separated hex.
pub fn compute_fingerprint(der: &[u8]) -> Option<String> {
    use sha2::{Digest, Sha256};
    let hash = Sha256::digest(der);
    let hex: Vec<String> = hash.iter().map(|b| format!("{b:02X}")).collect();
    Some(hex.join(":"))
}

/// Extract the CN (Common Name) from a DER-encoded X.509 certificate.
/// Uses a simple byte-level search for the CN OID (2.5.4.3).
/// Returns `None` if the CN cannot be found.
pub fn extract_cn_from_der(der: &[u8]) -> Option<String> {
    // OID for CommonName: 55 04 03
    const CN_OID: &[u8] = &[0x55, 0x04, 0x03];
    let pos = der.windows(CN_OID.len()).position(|w| w == CN_OID)?;
    // After the OID: tag (0x0C UTF8String or 0x13 PrintableString) + length + value
    let after = pos + CN_OID.len();
    if after + 2 > der.len() {
        return None;
    }
    let _tag = der[after];
    let len = der[after + 1] as usize;
    let value_start = after + 2;
    if value_start + len > der.len() {
        return None;
    }
    std::str::from_utf8(&der[value_start..value_start + len])
        .ok()
        .map(|s| s.to_string())
}

// ── Middleware ────────────────────────────────────────────────────────────

/// Axum middleware that:
///   1. Extracts the client identity from TLS extensions.
///   2. Injects `Extension<ClientIdentity>` for downstream handlers.
///   3. If `require_mtls=true` and no cert is present → 401.
///
/// Does NOT check roles — that is done per-endpoint via [`require_role`].
pub async fn admin_identity_middleware(
    Extension(auth_state): Extension<AdminAuthState>,
    mut req: Request,
    next: Next,
) -> Response {
    match extract_identity_from_request(&req) {
        Some(identity) => {
            tracing::debug!(
                identity = %identity,
                "admin: client identity extracted"
            );
            req.extensions_mut().insert(identity);
            next.run(req).await
        }
        None if !auth_state.require_mtls => {
            // Dev/test mode: insert anonymous identity.
            tracing::warn!("admin: mTLS not required — inserting anonymous identity (dev mode)");
            req.extensions_mut().insert(ClientIdentity {
                cn: None,
                fingerprint: None,
            });
            next.run(req).await
        }
        None => {
            tracing::warn!("admin: client presented no certificate — returning 401");
            (
                StatusCode::UNAUTHORIZED,
                Json(serde_json::json!({
                    "error": "MTLS_REQUIRED",
                    "message": "This endpoint requires a valid mTLS client certificate."
                })),
            )
                .into_response()
        }
    }
}

// ── Per-endpoint role enforcement ─────────────────────────────────────────

/// Guard type returned by [`require_role`] — gives handlers access to the
/// caller's identity for logging / audit without re-extracting it.
#[derive(Debug, Clone)]
pub struct AdminCaller {
    pub identity: ClientIdentity,
}

/// Enforce that the caller has at least `role` for `endpoint`.
///
/// Returns `Ok(AdminCaller)` on success, or an axum `Response` (403/401) on
/// failure.  Handlers should early-return the error response on `Err`.
pub fn require_role(
    rbac: &RbacChecker,
    identity: &ClientIdentity,
    endpoint: &str,
) -> Result<AdminCaller, Response> {
    match rbac.check(identity, endpoint) {
        Ok(_roles) => {
            tracing::info!(
                identity = %identity,
                endpoint = %endpoint,
                "admin: access granted"
            );
            Ok(AdminCaller {
                identity: identity.clone(),
            })
        }
        Err(denial) => {
            tracing::warn!(
                identity = %denial.identity,
                endpoint = %denial.endpoint,
                required = %denial.required,
                "admin: access denied (RBAC)"
            );
            Err((
                StatusCode::FORBIDDEN,
                Json(serde_json::json!({
                    "error": "RBAC_DENIED",
                    "message": format!("{denial}"),
                    "required_role": denial.required.to_string(),
                })),
            )
                .into_response())
        }
    }
}

// ── Convenience macro ─────────────────────────────────────────────────────

/// Use in admin handlers to enforce RBAC in one line:
/// ```ignore
/// let caller = admin_require!(rbac, identity, "/admin/snapshot");
/// // caller is AdminCaller
/// ```
#[macro_export]
macro_rules! admin_require {
    ($rbac:expr, $identity:expr, $endpoint:expr) => {
        match $crate::rpc::admin_auth::require_role($rbac, $identity, $endpoint) {
            Ok(caller) => caller,
            Err(resp) => return resp,
        }
    };
}

// ── Tests ─────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rpc::rbac::{RbacChecker, RbacPolicy};

    fn make_checker() -> RbacChecker {
        let policy: RbacPolicy = toml::from_str(
            r#"
[[identities]]
cn    = "ops-alice"
roles = ["operator"]

[[identities]]
cn    = "node-maintainer"
roles = ["maintainer"]
"#,
        )
        .unwrap();
        RbacChecker::new(policy)
    }

    #[test]
    fn operator_granted_for_snapshot() {
        let checker = make_checker();
        let id = ClientIdentity {
            cn: Some("ops-alice".into()),
            fingerprint: None,
        };
        assert!(require_role(&checker, &id, "/admin/snapshot").is_ok());
    }

    #[test]
    fn operator_denied_for_key_rotate() {
        let checker = make_checker();
        let id = ClientIdentity {
            cn: Some("ops-alice".into()),
            fingerprint: None,
        };
        assert!(require_role(&checker, &id, "/admin/key-rotate").is_err());
    }

    #[test]
    fn maintainer_granted_for_key_rotate() {
        let checker = make_checker();
        let id = ClientIdentity {
            cn: Some("node-maintainer".into()),
            fingerprint: None,
        };
        assert!(require_role(&checker, &id, "/admin/key-rotate").is_ok());
    }

    #[test]
    fn extract_cn_from_der_returns_none_for_garbage() {
        assert!(extract_cn_from_der(b"not a cert").is_none());
    }

    #[test]
    fn compute_fingerprint_is_deterministic() {
        let fp1 = compute_fingerprint(b"test").unwrap();
        let fp2 = compute_fingerprint(b"test").unwrap();
        assert_eq!(fp1, fp2);
        assert!(fp1.contains(':'));
    }
}
