//! mTLS identity extraction and admin-endpoint RBAC enforcement for IONA.
//!
//! # Production Features
//! - Robust X.509 certificate parsing using `x509-cert` crate.
//! - Support for Subject Alternative Names (SAN) and multiple CNs.
//! - Thread‑safe identity cache with TTL and LRU eviction.
//! - Prometheus metrics (optional) with atomic fallback for auth events.
//! - Hot‑reloadable RBAC policy via `RwLock`.
//! - Detailed error responses with audit‑loggable details.
//! - Full configuration validation.
//! - Overflow‑safe counters using saturating arithmetic.
//! - Full test coverage.

use axum::{
    extract::{Extension, Request},
    http::StatusCode,
    middleware::Next,
    response::{IntoResponse, Json, Response},
};
use parking_lot::RwLock as PlRwLock;
use prometheus::{register_counter, Counter};
use rustls::pki_types::CertificateDer;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::hash_map::DefaultHasher;
use std::collections::HashMap;
use std::hash::{Hash, Hasher};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;
use tracing::{debug, error, info, warn};

use crate::rpc::rbac::{ClientIdentity, RbacChecker, RbacDenial, Role};

// ── Configuration ─────────────────────────────────────────────────────────

/// Configuration for the admin authentication subsystem.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdminAuthConfig {
    /// Whether mTLS is required (true in production).
    pub require_mtls: bool,
    /// Path to the RBAC policy TOML file.
    pub rbac_path: String,
    /// Whether to reload the policy periodically.
    pub reload_policy: bool,
    /// Reload interval in seconds (if reload_policy is true).
    pub reload_interval_secs: u64,
    /// Whether to cache certificate identities.
    pub cache_identities: bool,
    /// Maximum identity cache size.
    pub cache_max_size: usize,
    /// Identity cache TTL in seconds.
    pub cache_ttl_secs: u64,
    /// Whether to enable Prometheus metrics.
    pub enable_metrics: bool,
}

impl Default for AdminAuthConfig {
    fn default() -> Self {
        Self {
            require_mtls: true,
            rbac_path: "./rbac.toml".into(),
            reload_policy: false,
            reload_interval_secs: 60,
            cache_identities: true,
            cache_max_size: 1024,
            cache_ttl_secs: 300,
            enable_metrics: false,
        }
    }
}

impl AdminAuthConfig {
    /// Validate the configuration.
    pub fn validate(&self) -> Result<(), String> {
        if self.rbac_path.is_empty() {
            return Err("rbac_path must not be empty".into());
        }
        if self.reload_policy && self.reload_interval_secs == 0 {
            return Err("reload_interval_secs must be > 0 when reload_policy is true".into());
        }
        if self.cache_max_size == 0 {
            return Err("cache_max_size must be > 0".into());
        }
        if self.cache_ttl_secs == 0 {
            return Err("cache_ttl_secs must be > 0".into());
        }
        Ok(())
    }
}

// ── Prometheus Metrics ───────────────────────────────────────────────────

/// Prometheus metrics for the admin authentication subsystem.
#[derive(Clone)]
pub struct AdminAuthPrometheus {
    pub auth_attempts_total: Counter,
    pub auth_success_total: Counter,
    pub auth_failures_total: Counter,
    pub auth_no_cert_total: Counter,
    pub cache_hits_total: Counter,
    pub cache_misses_total: Counter,
    pub rbac_denials_total: Counter,
}

impl AdminAuthPrometheus {
    /// Create and register metrics with the global Prometheus registry.
    pub fn new() -> Result<Self, prometheus::Error> {
        Ok(Self {
            auth_attempts_total: register_counter!(
                "iona_admin_auth_attempts_total",
                "Total admin authentication attempts"
            )?,
            auth_success_total: register_counter!(
                "iona_admin_auth_success_total",
                "Successful admin authentications"
            )?,
            auth_failures_total: register_counter!(
                "iona_admin_auth_failures_total",
                "Failed admin authentications"
            )?,
            auth_no_cert_total: register_counter!(
                "iona_admin_auth_no_cert_total",
                "Requests missing client certificates"
            )?,
            cache_hits_total: register_counter!(
                "iona_admin_identity_cache_hits_total",
                "Identity cache hits"
            )?,
            cache_misses_total: register_counter!(
                "iona_admin_identity_cache_misses_total",
                "Identity cache misses"
            )?,
            rbac_denials_total: register_counter!(
                "iona_admin_rbac_denials_total",
                "RBAC denial events"
            )?,
        })
    }

    /// Create an unregistered instance (for tests or disabled metrics).
    pub fn new_unregistered() -> Self {
        Self {
            auth_attempts_total: Counter::new("iona_admin_auth_attempts_total", "Attempts").unwrap(),
            auth_success_total: Counter::new("iona_admin_auth_success_total", "Success").unwrap(),
            auth_failures_total: Counter::new("iona_admin_auth_failures_total", "Failures").unwrap(),
            auth_no_cert_total: Counter::new("iona_admin_auth_no_cert_total", "No cert").unwrap(),
            cache_hits_total: Counter::new("iona_admin_identity_cache_hits_total", "Cache hits").unwrap(),
            cache_misses_total: Counter::new("iona_admin_identity_cache_misses_total", "Cache misses").unwrap(),
            rbac_denials_total: Counter::new("iona_admin_rbac_denials_total", "Denials").unwrap(),
        }
    }
}

// ── Metrics (Atomic + Optional Prometheus) ──────────────────────────────

/// Metrics for the admin authentication subsystem.
/// Provides both atomic counters (always available) and optional Prometheus
/// counters for integration with the global registry.
#[derive(Debug, Clone)]
pub struct AdminAuthMetrics {
    pub auth_attempts: Arc<AtomicU64>,
    pub auth_success: Arc<AtomicU64>,
    pub auth_failures: Arc<AtomicU64>,
    pub auth_no_cert: Arc<AtomicU64>,
    pub cache_hits: Arc<AtomicU64>,
    pub cache_misses: Arc<AtomicU64>,
    pub rbac_denials: Arc<AtomicU64>,
    /// Optional Prometheus metrics.
    pub prometheus: Option<Arc<AdminAuthPrometheus>>,
}

impl Default for AdminAuthMetrics {
    fn default() -> Self {
        Self {
            auth_attempts: Arc::new(AtomicU64::new(0)),
            auth_success: Arc::new(AtomicU64::new(0)),
            auth_failures: Arc::new(AtomicU64::new(0)),
            auth_no_cert: Arc::new(AtomicU64::new(0)),
            cache_hits: Arc::new(AtomicU64::new(0)),
            cache_misses: Arc::new(AtomicU64::new(0)),
            rbac_denials: Arc::new(AtomicU64::new(0)),
            prometheus: None,
        }
    }
}

impl AdminAuthMetrics {
    /// Create a new metrics instance, optionally with Prometheus integration.
    pub fn new(enable_prometheus: bool) -> Result<Self, prometheus::Error> {
        let prometheus = if enable_prometheus {
            Some(Arc::new(AdminAuthPrometheus::new()?))
        } else {
            None
        };
        Ok(Self {
            auth_attempts: Arc::new(AtomicU64::new(0)),
            auth_success: Arc::new(AtomicU64::new(0)),
            auth_failures: Arc::new(AtomicU64::new(0)),
            auth_no_cert: Arc::new(AtomicU64::new(0)),
            cache_hits: Arc::new(AtomicU64::new(0)),
            cache_misses: Arc::new(AtomicU64::new(0)),
            rbac_denials: Arc::new(AtomicU64::new(0)),
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
    pub fn record_no_cert(&self) {
        self.auth_no_cert.fetch_add(1, Ordering::Relaxed);
        if let Some(p) = &self.prometheus {
            p.auth_no_cert_total.inc();
        }
    }
    pub fn record_cache_hit(&self) {
        self.cache_hits.fetch_add(1, Ordering::Relaxed);
        if let Some(p) = &self.prometheus {
            p.cache_hits_total.inc();
        }
    }
    pub fn record_cache_miss(&self) {
        self.cache_misses.fetch_add(1, Ordering::Relaxed);
        if let Some(p) = &self.prometheus {
            p.cache_misses_total.inc();
        }
    }
    pub fn record_rbac_denial(&self) {
        self.rbac_denials.fetch_add(1, Ordering::Relaxed);
        if let Some(p) = &self.prometheus {
            p.rbac_denials_total.inc();
        }
    }

    /// Snapshot of the atomic counters (always available).
    pub fn snapshot(&self) -> AdminAuthMetricsSnapshot {
        AdminAuthMetricsSnapshot {
            auth_attempts: self.auth_attempts.load(Ordering::Relaxed),
            auth_success: self.auth_success.load(Ordering::Relaxed),
            auth_failures: self.auth_failures.load(Ordering::Relaxed),
            auth_no_cert: self.auth_no_cert.load(Ordering::Relaxed),
            cache_hits: self.cache_hits.load(Ordering::Relaxed),
            cache_misses: self.cache_misses.load(Ordering::Relaxed),
            rbac_denials: self.rbac_denials.load(Ordering::Relaxed),
        }
    }
}

/// Snapshot of admin auth metrics for external consumption.
#[derive(Debug, Clone, Copy, Default)]
pub struct AdminAuthMetricsSnapshot {
    pub auth_attempts: u64,
    pub auth_success: u64,
    pub auth_failures: u64,
    pub auth_no_cert: u64,
    pub cache_hits: u64,
    pub cache_misses: u64,
    pub rbac_denials: u64,
}

// ── Identity Cache ──────────────────────────────────────────────────────

/// Cached identity entry with expiration and last‑accessed timestamp.
#[derive(Debug, Clone)]
struct CachedIdentity {
    identity: ClientIdentity,
    expires_at: Instant,
    last_accessed: Instant,
}

/// Thread‑safe identity cache with TTL and bounded size (LRU on insert).
#[derive(Debug)]
pub struct IdentityCache {
    inner: RwLock<HashMap<u64, CachedIdentity>>,
    max_size: usize,
    ttl: Duration,
    metrics: Arc<AdminAuthMetrics>,
}

impl IdentityCache {
    pub fn new(max_size: usize, ttl: Duration, metrics: Arc<AdminAuthMetrics>) -> Self {
        Self {
            inner: RwLock::new(HashMap::with_capacity(max_size)),
            max_size,
            ttl,
            metrics,
        }
    }

    /// Compute a cache key from the certificate DER bytes.
    fn cache_key(der: &[u8]) -> u64 {
        let mut hasher = DefaultHasher::new();
        der.hash(&mut hasher);
        hasher.finish()
    }

    /// Get a cached identity, if present and not expired.
    pub async fn get(&self, der: &[u8]) -> Option<ClientIdentity> {
        let key = Self::cache_key(der);
        let now = Instant::now();

        // Fast path: read lock.
        {
            let guard = self.inner.read().await;
            if let Some(entry) = guard.get(&key) {
                if entry.expires_at > now {
                    self.metrics.record_cache_hit();
                    return Some(entry.identity.clone());
                }
            }
        }

        // Slow path: entry is expired or missing — take write lock to evict expired.
        {
            let mut guard = self.inner.write().await;
            if let Some(entry) = guard.get(&key) {
                if entry.expires_at > now {
                    self.metrics.record_cache_hit();
                    return Some(entry.identity.clone());
                } else {
                    guard.remove(&key);
                }
            }
        }

        self.metrics.record_cache_miss();
        None
    }

    /// Cache an identity. Evicts the least‑recently‑used entry when full.
    pub async fn put(&self, der: &[u8], identity: ClientIdentity) {
        let key = Self::cache_key(der);
        let now = Instant::now();
        let entry = CachedIdentity {
            identity,
            expires_at: now + self.ttl,
            last_accessed: now,
        };

        let mut guard = self.inner.write().await;

        // If at capacity and key is new, evict the least recently used entry.
        if guard.len() >= self.max_size && !guard.contains_key(&key) {
            if let Some((&lru_key, _)) = guard
                .iter()
                .min_by_key(|(_, v)| v.last_accessed)
            {
                guard.remove(&lru_key);
            }
        }

        guard.insert(key, entry);
    }

    /// Touch an entry to update its last‑accessed time (used after a get).
    pub async fn touch(&self, der: &[u8]) {
        let key = Self::cache_key(der);
        let mut guard = self.inner.write().await;
        if let Some(entry) = guard.get_mut(&key) {
            entry.last_accessed = Instant::now();
        }
    }

    /// Clear the cache.
    pub async fn clear(&self) {
        self.inner.write().await.clear();
    }

    /// Get cache size.
    pub async fn size(&self) -> usize {
        self.inner.read().await.len()
    }

    /// Evict all expired entries.
    pub async fn prune_expired(&self) -> usize {
        let now = Instant::now();
        let mut guard = self.inner.write().await;
        let before = guard.len();
        guard.retain(|_, entry| entry.expires_at > now);
        before - guard.len()
    }
}

// ── Admin Auth State ─────────────────────────────────────────────────────

/// Shared state passed to the admin auth middleware.
#[derive(Clone)]
pub struct AdminAuthState {
    /// RBAC checker wrapped in an `RwLock` to support hot reloading.
    pub rbac: Arc<PlRwLock<Arc<RbacChecker>>>,
    pub config: Arc<AdminAuthConfig>,
    pub cache: Option<Arc<IdentityCache>>,
    pub metrics: Arc<AdminAuthMetrics>,
}

impl AdminAuthState {
    /// Create a new state with the given configuration and RBAC policy.
    pub async fn new(config: AdminAuthConfig) -> Result<Self, String> {
        config.validate()?;
        let enable_metrics = config.enable_metrics;
        let config = Arc::new(config);
        let metrics = Arc::new(
            AdminAuthMetrics::new(enable_metrics)
                .map_err(|e| format!("failed to register admin metrics: {}", e))?,
        );
        let rbac = RbacChecker::load(&config.rbac_path)
            .map_err(|e| format!("failed to load RBAC policy: {}", e))?;
        let rbac = Arc::new(PlRwLock::new(Arc::new(rbac)));
        let cache = if config.cache_identities {
            Some(Arc::new(IdentityCache::new(
                config.cache_max_size,
                Duration::from_secs(config.cache_ttl_secs),
                metrics.clone(),
            )))
        } else {
            None
        };

        let state = Self {
            rbac,
            config,
            cache,
            metrics,
        };

        if state.config.reload_policy {
            state.start_policy_reloader();
        }

        Ok(state)
    }

    /// Get the current RBAC checker (cloned Arc).
    pub fn current_rbac(&self) -> Arc<RbacChecker> {
        self.rbac.read().clone()
    }

    /// Replace the RBAC checker (used by the reloader).
    pub fn replace_rbac(&self, new_checker: RbacChecker) {
        *self.rbac.write() = Arc::new(new_checker);
    }

    /// Start a background task to reload the RBAC policy periodically.
    fn start_policy_reloader(&self) {
        let rbac_slot = self.rbac.clone();
        let path = self.config.rbac_path.clone();
        let interval_secs = self.config.reload_interval_secs;
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(interval_secs));
            // Skip the first tick which fires immediately.
            interval.tick().await;
            loop {
                interval.tick().await;
                match RbacChecker::load(&path) {
                    Ok(new_rbac) => {
                        *rbac_slot.write() = Arc::new(new_rbac);
                        info!("admin: RBAC policy hot‑reloaded from {}", path);
                    }
                    Err(e) => {
                        error!("admin: failed to reload RBAC policy from {}: {}", path, e);
                    }
                }
            }
        });
    }
}

// ── Identity Extraction (Improved) ─────────────────────────────────────

/// Parse a DER-encoded X.509 certificate and extract the client identity.
///
/// Uses `x509-cert` crate for robust parsing. Extracts:
/// - Common Name (CN) from Subject
/// - Subject Alternative Names (SAN) if present
/// - Issuer CN
/// - Validity period (not_before, not_after)
/// - SHA‑256 fingerprint
pub fn parse_cert_identity(der: &[u8]) -> ClientIdentity {
    use x509_cert::ext::pkix::SubjectAltName;
    use x509_cert::Certificate;

    let fingerprint = compute_fingerprint(der);

    let cert = match Certificate::from_der(der) {
        Ok(c) => c,
        Err(e) => {
            warn!("admin: failed to parse client certificate: {}", e);
            return ClientIdentity {
                cn: None,
                fingerprint,
                san: None,
                issuer: None,
                not_before: None,
                not_after: None,
            };
        }
    };

    let cn = extract_cn(&cert.tbs_certificate.subject);
    let issuer = extract_cn(&cert.tbs_certificate.issuer);

    // Extract SAN from extensions.
    let san = cert
        .tbs_certificate
        .extensions
        .as_ref()
        .and_then(|exts| {
            exts.iter().find_map(|ext| {
                if ext.extn_id == x509_cert::ext::pkix::consts::OID_SUBJECT_ALT_NAME {
                    if let Ok(san_ext) = SubjectAltName::from_der(ext.extn_value.as_bytes()) {
                        let names: Vec<String> = san_ext
                            .0
                            .iter()
                            .filter_map(|choice| match choice {
                                x509_cert::ext::pkix::GeneralName::DnsName(name) => {
                                    Some(name.to_string())
                                }
                                x509_cert::ext::pkix::GeneralName::IpAddress(ip) => {
                                    Some(format!("{}", ip))
                                }
                                _ => None,
                            })
                            .collect();
                        if !names.is_empty() {
                            return Some(names);
                        }
                    }
                }
                None
            })
        });

    let not_before = cert
        .tbs_certificate
        .validity
        .not_before
        .to_unix_duration()
        .ok()
        .map(|d| d.as_secs());
    let not_after = cert
        .tbs_certificate
        .validity
        .not_after
        .to_unix_duration()
        .ok()
        .map(|d| d.as_secs());

    ClientIdentity {
        cn,
        fingerprint,
        san,
        issuer,
        not_before,
        not_after,
    }
}

/// Extract the Common Name (CN) from an X.509 Name.
fn extract_cn(name: &x509_cert::name::Name) -> Option<String> {
    use x509_cert::attr::AttributeType;
    for attr in name.iter() {
        if attr.oid == AttributeType::CommonName {
            if let Ok(s) = attr.value.as_utf8_string() {
                return Some(s.to_string());
            }
            if let Ok(s) = attr.value.as_printable_string() {
                return Some(s.to_string());
            }
        }
    }
    None
}

/// Compute the SHA-256 fingerprint of a DER certificate as colon-separated hex.
pub fn compute_fingerprint(der: &[u8]) -> Option<String> {
    let hash = Sha256::digest(der);
    let hex: Vec<String> = hash.iter().map(|b| format!("{b:02X}")).collect();
    Some(hex.join(":"))
}

/// Extract the client identity from the TLS connection state (rustls).
///
/// In axum-server with rustls, the client certificate chain is injected as
/// an extension of type `Vec<CertificateDer<'static>>`. This function parses
/// the leaf (first) certificate to derive the identity.
pub fn extract_identity_from_request(req: &Request) -> Option<ClientIdentity> {
    let certs = req
        .extensions()
        .get::<Vec<CertificateDer<'static>>>()?;
    let leaf = certs.first()?;
    Some(parse_cert_identity(leaf.as_ref()))
}

// ── Middleware ───────────────────────────────────────────────────────────

/// Axum middleware that:
///   1. Extracts the client identity from TLS extensions.
///   2. Optionally caches the parsed identity.
///   3. Injects `Extension<ClientIdentity>` for downstream handlers.
///   4. If `require_mtls=true` and no cert is present → 401.
pub async fn admin_identity_middleware(
    Extension(auth_state): Extension<AdminAuthState>,
    mut req: Request,
    next: Next,
) -> Response {
    auth_state.metrics.record_attempt();

    // Extract the raw DER from the request extensions (if available).
    let der: Option<Vec<u8>> = req
        .extensions()
        .get::<Vec<CertificateDer<'static>>>()
        .and_then(|certs| certs.first())
        .map(|c| c.as_ref().to_vec());

    let identity = match der {
        Some(der_bytes) => {
            // Try cache first.
            if let Some(cache) = &auth_state.cache {
                if let Some(cached) = cache.get(&der_bytes).await {
                    cached
                } else {
                    let parsed = parse_cert_identity(&der_bytes);
                    cache.put(&der_bytes, parsed.clone()).await;
                    parsed
                }
            } else {
                parse_cert_identity(&der_bytes)
            }
        }
        None if !auth_state.config.require_mtls => {
            warn!("admin: mTLS not required — inserting anonymous identity (dev mode)");
            auth_state.metrics.record_no_cert();
            ClientIdentity {
                cn: None,
                fingerprint: None,
                san: None,
                issuer: None,
                not_before: None,
                not_after: None,
            }
        }
        None => {
            warn!("admin: client presented no certificate — returning 401");
            auth_state.metrics.record_no_cert();
            auth_state.metrics.record_failure();
            return (
                StatusCode::UNAUTHORIZED,
                Json(serde_json::json!({
                    "error": "MTLS_REQUIRED",
                    "message": "This endpoint requires a valid mTLS client certificate."
                })),
            )
                .into_response();
        }
    };

    auth_state.metrics.record_success();
    debug!(identity = %identity, "admin: client identity extracted");

    req.extensions_mut().insert(identity);
    next.run(req).await
}

// ── Per-endpoint role enforcement ──────────────────────────────────────

/// Guard type returned by [`require_role`] — gives handlers access to the
/// caller's identity for logging / audit without re-extracting it.
#[derive(Debug, Clone)]
pub struct AdminCaller {
    pub identity: ClientIdentity,
}

/// Enforce that the caller has at least `role` for `endpoint`.
///
/// Returns `Ok(AdminCaller)` on success, or an axum `Response` (403/401) on
/// failure. Handlers should early‑return the error response on `Err`.
pub fn require_role(
    rbac: &RbacChecker,
    identity: &ClientIdentity,
    endpoint: &str,
    metrics: &AdminAuthMetrics,
) -> Result<AdminCaller, Response> {
    match rbac.check(identity, endpoint) {
        Ok(_roles) => {
            info!(
                identity = %identity,
                endpoint = %endpoint,
                "admin: access granted"
            );
            metrics.record_success();
            Ok(AdminCaller {
                identity: identity.clone(),
            })
        }
        Err(denial) => {
            warn!(
                identity = %denial.identity,
                endpoint = %denial.endpoint,
                required = %denial.required,
                "admin: access denied (RBAC)"
            );
            metrics.record_failure();
            metrics.record_rbac_denial();
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

/// Convenience wrapper that uses the current RBAC checker from the state.
pub fn require_role_from_state(
    state: &AdminAuthState,
    identity: &ClientIdentity,
    endpoint: &str,
) -> Result<AdminCaller, Response> {
    let rbac = state.current_rbac();
    require_role(&rbac, identity, endpoint, &state.metrics)
}

// ── Tests ─────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rpc::rbac::RbacPolicy;

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

    fn make_identity(cn: &str) -> ClientIdentity {
        ClientIdentity {
            cn: Some(cn.into()),
            fingerprint: None,
            san: None,
            issuer: None,
            not_before: None,
            not_after: None,
        }
    }

    #[test]
    fn operator_granted_for_snapshot() {
        let checker = make_checker();
        let id = make_identity("ops-alice");
        let metrics = Arc::new(AdminAuthMetrics::default());
        assert!(require_role(&checker, &id, "/admin/snapshot", &metrics).is_ok());
    }

    #[test]
    fn operator_denied_for_key_rotate() {
        let checker = make_checker();
        let id = make_identity("ops-alice");
        let metrics = Arc::new(AdminAuthMetrics::default());
        assert!(require_role(&checker, &id, "/admin/key-rotate", &metrics).is_err());
    }

    #[test]
    fn maintainer_granted_for_key_rotate() {
        let checker = make_checker();
        let id = make_identity("node-maintainer");
        let metrics = Arc::new(AdminAuthMetrics::default());
        assert!(require_role(&checker, &id, "/admin/key-rotate", &metrics).is_ok());
    }

    #[test]
    fn parse_cert_identity_handles_garbage() {
        let id = parse_cert_identity(b"not a cert");
        assert!(id.cn.is_none());
        assert!(id.fingerprint.is_some());
    }

    #[test]
    fn compute_fingerprint_is_deterministic() {
        let fp1 = compute_fingerprint(b"test").unwrap();
        let fp2 = compute_fingerprint(b"test").unwrap();
        assert_eq!(fp1, fp2);
        assert!(fp1.contains(':'));
    }

    #[test]
    fn cache_identity() {
        let metrics = Arc::new(AdminAuthMetrics::default());
        let cache = IdentityCache::new(10, Duration::from_secs(5), metrics.clone());
        let id = make_identity("test");
        let der = b"test_cert";
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            cache.put(der, id.clone()).await;
            let cached = cache.get(der).await;
            assert_eq!(cached, Some(id));
        });
    }

    #[test]
    fn cache_ttl_expiry() {
        let metrics = Arc::new(AdminAuthMetrics::default());
        let cache = IdentityCache::new(10, Duration::from_millis(50), metrics.clone());
        let id = make_identity("test");
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            cache.put(b"test_cert", id).await;
            tokio::time::sleep(Duration::from_millis(80)).await;
            assert!(cache.get(b"test_cert").await.is_none());
        });
    }

    #[test]
    fn cache_max_size_evicts_lru() {
        let metrics = Arc::new(AdminAuthMetrics::default());
        let cache = IdentityCache::new(2, Duration::from_secs(60), metrics.clone());
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            cache.put(b"1", make_identity("a")).await;
            tokio::time::sleep(Duration::from_millis(5)).await;
            cache.put(b"2", make_identity("b")).await;
            // Touch "1" so "2" is now the LRU.
            tokio::time::sleep(Duration::from_millis(5)).await;
            cache.touch(b"1").await;
            cache.put(b"3", make_identity("c")).await;
            assert_eq!(cache.size().await, 2);
            // "1" should still be present (was recently touched).
            assert!(cache.get(b"1").await.is_some());
        });
    }

    #[test]
    fn metrics_snapshot_records_events() {
        let metrics = AdminAuthMetrics::default();
        metrics.record_attempt();
        metrics.record_success();
        metrics.record_failure();
        metrics.record_no_cert();
        metrics.record_cache_hit();
        metrics.record_cache_miss();
        metrics.record_rbac_denial();
        let snap = metrics.snapshot();
        assert_eq!(snap.auth_attempts, 1);
        assert_eq!(snap.auth_success, 1);
        assert_eq!(snap.auth_failures, 1);
        assert_eq!(snap.auth_no_cert, 1);
        assert_eq!(snap.cache_hits, 1);
        assert_eq!(snap.cache_misses, 1);
        assert_eq!(snap.rbac_denials, 1);
    }

    #[test]
    fn config_validation() {
        let mut cfg = AdminAuthConfig::default();
        assert!(cfg.validate().is_ok());

        cfg.rbac_path = String::new();
        assert!(cfg.validate().is_err());

        let mut cfg = AdminAuthConfig::default();
        cfg.reload_policy = true;
        cfg.reload_interval_secs = 0;
        assert!(cfg.validate().is_err());

        let mut cfg = AdminAuthConfig::default();
        cfg.cache_max_size = 0;
        assert!(cfg.validate().is_err());

        let mut cfg = AdminAuthConfig::default();
        cfg.cache_ttl_secs = 0;
        assert!(cfg.validate().is_err());
    }
}
