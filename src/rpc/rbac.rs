//! Role-Based Access Control (RBAC) for the IONA admin RPC.
//!
//! Identities are mTLS client certificates; their CN or SHA-256 fingerprint is
//! extracted by [`admin_auth`](crate::rpc::admin_auth) and looked up here to
//! determine which roles (and therefore which endpoints) the caller may access.
//!
//! ## Role hierarchy
//!
//! | Role         | Can do                                                        |
//! |--------------|---------------------------------------------------------------|
//! | `auditor`    | Read-only: `/admin/status`, `/admin/audit`                    |
//! | `operator`   | + node control: restart, snapshot, peer-kick, config-reload   |
//! | `maintainer` | + everything: key rotation, upgrade triggers, schema ops      |
//!
//! ## Configuration (`rbac.toml`)
//!
//! ```toml
//! [[identities]]
//! cn          = "ops-alice"
//! fingerprint = "AA:BB:CC:..."
//! roles       = ["operator"]
//!
//! [[identities]]
//! cn    = "ci-bot"
//! roles = ["auditor"]
//! ```
//!
//! Both `cn` and `fingerprint` are optional individually, but at least one must
//! be present. If both are provided, **both** must match the presented cert.

use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use thiserror::Error;

// -----------------------------------------------------------------------------
// Constants
// -----------------------------------------------------------------------------

/// Default RBAC policy file name.
pub const DEFAULT_RBAC_FILENAME: &str = "rbac.toml";

/// Admin endpoints and their required minimum role.
pub mod endpoints {
    pub const STATUS: &str = "/admin/status";
    pub const AUDIT: &str = "/admin/audit";
    pub const METRICS: &str = "/admin/metrics";
    pub const SNAPSHOT: &str = "/admin/snapshot";
    pub const PEER_KICK: &str = "/admin/peer-kick";
    pub const CONFIG_RELOAD: &str = "/admin/config-reload";
    pub const MEMPOOL_FLUSH: &str = "/admin/mempool-flush";
    pub const KEY_ROTATE: &str = "/admin/key-rotate";
    pub const UPGRADE_TRIGGER: &str = "/admin/upgrade-trigger";
    pub const RESET_CHAIN: &str = "/admin/reset-chain";
    pub const SCHEMA_MIGRATE: &str = "/admin/schema-migrate";
}

// -----------------------------------------------------------------------------
// Errors
// -----------------------------------------------------------------------------

/// Errors that can occur during RBAC operations.
#[derive(Debug, Error)]
pub enum RbacError {
    #[error("I/O error reading RBAC file {path}: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("TOML parse error in {path}: {source}")]
    Toml {
        path: PathBuf,
        #[source]
        source: toml::de::Error,
    },
    #[error("invalid RBAC policy: {0}")]
    InvalidPolicy(String),
}

pub type RbacResult<T> = Result<T, RbacError>;

// -----------------------------------------------------------------------------
// Role definitions
// -----------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Role {
    Auditor,
    Operator,
    Maintainer,
}

impl Role {
    /// Returns true if this role subsumes (is at least as powerful as) `other`.
    pub fn subsumes(&self, other: &Role) -> bool {
        match (self, other) {
            (Role::Maintainer, _) => true,
            (Role::Operator, Role::Operator) | (Role::Operator, Role::Auditor) => true,
            (Role::Auditor, Role::Auditor) => true,
            _ => false,
        }
    }
}

impl std::fmt::Display for Role {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Role::Auditor => write!(f, "auditor"),
            Role::Operator => write!(f, "operator"),
            Role::Maintainer => write!(f, "maintainer"),
        }
    }
}

// -----------------------------------------------------------------------------
// Endpoint permission map
// -----------------------------------------------------------------------------

/// Returns the minimum role required to call an admin endpoint.
pub fn required_role(endpoint: &str) -> Role {
    match endpoint {
        // Read-only — any authenticated identity
        endpoints::STATUS | endpoints::AUDIT | endpoints::METRICS => Role::Auditor,
        // Node control — operator and above
        endpoints::SNAPSHOT
        | endpoints::PEER_KICK
        | endpoints::CONFIG_RELOAD
        | endpoints::MEMPOOL_FLUSH => Role::Operator,
        // Destructive / privileged — maintainer only
        endpoints::KEY_ROTATE
        | endpoints::UPGRADE_TRIGGER
        | endpoints::RESET_CHAIN
        | endpoints::SCHEMA_MIGRATE => Role::Maintainer,
        // Default: deny unknown admin endpoints at the highest level
        _ => Role::Maintainer,
    }
}

// -----------------------------------------------------------------------------
// Identity
// -----------------------------------------------------------------------------

/// A verified client identity extracted from a mTLS certificate.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ClientIdentity {
    /// Common Name from the certificate Subject field.
    pub cn: Option<String>,
    /// SHA-256 fingerprint of the DER-encoded certificate (colon-hex).
    pub fingerprint: Option<String>,
}

impl std::fmt::Display for ClientIdentity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match (&self.cn, &self.fingerprint) {
            (Some(cn), Some(fp)) => write!(f, "CN={cn} fp={fp}"),
            (Some(cn), None) => write!(f, "CN={cn}"),
            (None, Some(fp)) => write!(f, "fp={fp}"),
            (None, None) => write!(f, "<unknown>"),
        }
    }
}

// -----------------------------------------------------------------------------
// RBAC policy file (rbac.toml)
// -----------------------------------------------------------------------------

/// A single identity→roles mapping entry in `rbac.toml`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RbacIdentityEntry {
    pub cn: Option<String>,
    pub fingerprint: Option<String>,
    pub roles: Vec<Role>,
}

impl RbacIdentityEntry {
    /// Validate that at least one of `cn` or `fingerprint` is provided.
    pub fn validate(&self) -> RbacResult<()> {
        if self.cn.is_none() && self.fingerprint.is_none() {
            return Err(RbacError::InvalidPolicy(
                "each identity must have at least `cn` or `fingerprint`".into(),
            ));
        }
        Ok(())
    }
}

/// The full RBAC policy loaded from `rbac.toml`.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RbacPolicy {
    pub identities: Vec<RbacIdentityEntry>,
}

impl RbacPolicy {
    /// Load from a TOML file.
    pub fn load(path: impl AsRef<Path>) -> RbacResult<Self> {
        let path = path.as_ref();
        let content = std::fs::read_to_string(path)
            .map_err(|e| RbacError::Io { path: path.to_path_buf(), source: e })?;
        let policy: Self = toml::from_str(&content)
            .map_err(|e| RbacError::Toml { path: path.to_path_buf(), source: e })?;
        // Validate each entry
        for entry in &policy.identities {
            entry.validate()?;
        }
        Ok(policy)
    }

    /// Returns the set of roles granted to `identity` based on this policy.
    pub fn roles_for(&self, identity: &ClientIdentity) -> HashSet<Role> {
        let mut result = HashSet::new();
        for entry in &self.identities {
            let cn_ok = match (&entry.cn, &identity.cn) {
                (Some(ecn), Some(icn)) => ecn.to_lowercase() == icn.to_lowercase(),
                (Some(_), None) => false,
                (None, _) => true,
            };
            let fp_ok = match (&entry.fingerprint, &identity.fingerprint) {
                (Some(efp), Some(ifp)) => efp == ifp,
                (Some(_), None) => false,
                (None, _) => true,
            };
            if cn_ok && fp_ok {
                result.extend(entry.roles.iter().cloned());
            }
        }
        result
    }

    /// Returns true if `identity` has at least `required` (respecting hierarchy).
    pub fn is_allowed(&self, identity: &ClientIdentity, required: &Role) -> bool {
        self.roles_for(identity)
            .iter()
            .any(|r| r.subsumes(required))
    }
}

// -----------------------------------------------------------------------------
// Runtime RBAC checker
// -----------------------------------------------------------------------------

/// Thread-safe runtime wrapper over an [`RbacPolicy`] with hot-reload support.
#[derive(Debug)]
pub struct RbacChecker {
    policy: parking_lot::RwLock<RbacPolicy>,
    path: Option<std::path::PathBuf>,
}

impl RbacChecker {
    /// Create from an already-loaded policy (or default empty policy).
    pub fn new(policy: RbacPolicy) -> Self {
        Self {
            policy: parking_lot::RwLock::new(policy),
            path: None,
        }
    }

    /// Load from file and record path for hot-reload.
    pub fn from_file(path: impl AsRef<Path>) -> RbacResult<Self> {
        let path = path.as_ref().to_path_buf();
        let policy = RbacPolicy::load(&path)?;
        Ok(Self {
            policy: parking_lot::RwLock::new(policy),
            path: Some(path),
        })
    }

    /// Hot-reload the policy from disk (if path was set).
    pub fn reload(&self) -> RbacResult<()> {
        if let Some(p) = &self.path {
            let new = RbacPolicy::load(p)?;
            *self.policy.write() = new;
        }
        Ok(())
    }

    /// Replace the in-memory policy directly (useful for tests).
    pub fn reload_policy(&self, new_policy: RbacPolicy) {
        *self.policy.write() = new_policy;
    }

    /// Check if the identity is allowed to access the endpoint.
    /// Returns `Ok(roles)` if allowed, otherwise `Err(RbacDenial)`.
    pub fn check(
        &self,
        identity: &ClientIdentity,
        endpoint: &str,
    ) -> Result<HashSet<Role>, RbacDenial> {
        let required = required_role(endpoint);
        let policy = self.policy.read();
        let roles = policy.roles_for(identity);
        if roles.iter().any(|r| r.subsumes(&required)) {
            Ok(roles)
        } else {
            Err(RbacDenial {
                identity: identity.clone(),
                endpoint: endpoint.to_string(),
                required,
                held: roles,
            })
        }
    }
}

// -----------------------------------------------------------------------------
// Denial reason
// -----------------------------------------------------------------------------

/// Reason why an RBAC check failed — returned as structured data for logging.
#[derive(Debug, Clone)]
pub struct RbacDenial {
    pub identity: ClientIdentity,
    pub endpoint: String,
    pub required: Role,
    pub held: HashSet<Role>,
}

impl std::fmt::Display for RbacDenial {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let held: Vec<_> = self.held.iter().map(|r| r.to_string()).collect();
        write!(
            f,
            "RBAC denied: identity={} endpoint={} required={} held=[{}]",
            self.identity,
            self.endpoint,
            self.required,
            held.join(",")
        )
    }
}

// -----------------------------------------------------------------------------
// Sample config generator
// -----------------------------------------------------------------------------

/// Write a sample `rbac.toml` to `path` for new deployments.
pub fn write_sample_rbac(path: impl AsRef<Path>) -> std::io::Result<()> {
    let sample = r#"# IONA RBAC policy — maps mTLS client identities to roles.
#
# Roles (in ascending order of privilege):
#   auditor    – read-only: /admin/status, /admin/audit, /admin/metrics
#   operator   – + snapshot, peer-kick, config-reload, mempool-flush
#   maintainer – + key-rotate, upgrade-trigger, reset-chain, schema-migrate
#
# For each identity, specify at least one of `cn` or `fingerprint`.
# If both are present, BOTH must match.

[[identities]]
cn    = "ops-alice"
roles = ["operator"]

[[identities]]
cn          = "ci-bot"
fingerprint = "AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99"
roles       = ["auditor"]

[[identities]]
cn    = "node-maintainer"
roles = ["maintainer"]
"#;
    std::fs::write(path.as_ref(), sample)
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::NamedTempFile;

    fn alice() -> ClientIdentity {
        ClientIdentity {
            cn: Some("ops-alice".into()),
            fingerprint: None,
        }
    }

    fn bot() -> ClientIdentity {
        ClientIdentity {
            cn: Some("ci-bot".into()),
            fingerprint: Some("AA:BB".into()),
        }
    }

    fn stranger() -> ClientIdentity {
        ClientIdentity {
            cn: Some("hacker".into()),
            fingerprint: None,
        }
    }

    fn policy() -> RbacPolicy {
        toml::from_str(
            r#"
[[identities]]
cn = "ops-alice"
roles = ["operator"]

[[identities]]
cn          = "ci-bot"
fingerprint = "AA:BB"
roles       = ["auditor"]

[[identities]]
cn = "node-maintainer"
roles = ["maintainer"]
"#,
        )
        .unwrap()
    }

    #[test]
    fn operator_can_access_operator_endpoint() {
        let p = policy();
        assert!(p.is_allowed(&alice(), &Role::Operator));
    }

    #[test]
    fn operator_can_access_auditor_endpoint() {
        let p = policy();
        assert!(p.is_allowed(&alice(), &Role::Auditor));
    }

    #[test]
    fn operator_cannot_access_maintainer_endpoint() {
        let p = policy();
        assert!(!p.is_allowed(&alice(), &Role::Maintainer));
    }

    #[test]
    fn auditor_cannot_access_operator_endpoint() {
        let p = policy();
        assert!(!p.is_allowed(&bot(), &Role::Operator));
    }

    #[test]
    fn unknown_identity_gets_no_roles() {
        let p = policy();
        assert!(p.roles_for(&stranger()).is_empty());
    }

    #[test]
    fn fingerprint_mismatch_denies() {
        let p = policy();
        let bad_fp = ClientIdentity {
            cn: Some("ci-bot".into()),
            fingerprint: Some("00:00".into()),
        };
        assert!(p.roles_for(&bad_fp).is_empty());
    }

    #[test]
    fn required_role_unknown_endpoint_is_maintainer() {
        assert_eq!(required_role("/admin/something-new"), Role::Maintainer);
    }

    #[test]
    fn checker_denies_stranger() {
        let checker = RbacChecker::new(policy());
        let result = checker.check(&stranger(), endpoints::STATUS);
        assert!(result.is_err());
        let denial = result.unwrap_err();
        assert_eq!(denial.required, Role::Auditor);
    }

    #[test]
    fn load_invalid_file() {
        let temp = NamedTempFile::new().unwrap();
        std::fs::write(temp.path(), b"invalid toml {").unwrap();
        let result = RbacPolicy::load(temp.path());
        assert!(result.is_err());
    }

    #[test]
    fn load_missing_file() {
        let result = RbacPolicy::load("/nonexistent/file.toml");
        assert!(result.is_err());
        if let Err(RbacError::Io { .. }) = result {
            // ok
        } else {
            panic!("expected Io error");
        }
    }

    #[test]
    fn entry_validation() {
        let valid = RbacIdentityEntry {
            cn: Some("alice".into()),
            fingerprint: None,
            roles: vec![Role::Auditor],
        };
        assert!(valid.validate().is_ok());

        let invalid = RbacIdentityEntry {
            cn: None,
            fingerprint: None,
            roles: vec![Role::Auditor],
        };
        assert!(invalid.validate().is_err());
    }
}
