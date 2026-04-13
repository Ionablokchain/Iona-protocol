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
use std::path::Path;

// ── Role definitions ──────────────────────────────────────────────────────

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

// ── Endpoint permission map ───────────────────────────────────────────────

/// Returns the minimum role required to call an admin endpoint.
pub fn required_role(endpoint: &str) -> Role {
    match endpoint {
        // Read-only — any authenticated identity
        "/admin/status" | "/admin/audit" | "/admin/metrics" => Role::Auditor,
        // Node control — operator and above
        "/admin/snapshot"
        | "/admin/peer-kick"
        | "/admin/config-reload"
        | "/admin/mempool-flush" => Role::Operator,
        // Destructive / privileged — maintainer only
        "/admin/key-rotate"
        | "/admin/upgrade-trigger"
        | "/admin/reset-chain"
        | "/admin/schema-migrate" => Role::Maintainer,
        // Default: deny unknown admin endpoints at the highest level
        _ => Role::Maintainer,
    }
}

// ── Identity ──────────────────────────────────────────────────────────────

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

// ── RBAC policy file (rbac.toml) ─────────────────────────────────────────

/// A single identity→roles mapping entry in `rbac.toml`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RbacIdentityEntry {
    /// Optional CN match (case-insensitive prefix match).
    pub cn: Option<String>,
    /// Optional SHA-256 fingerprint match (exact, colon-hex).
    pub fingerprint: Option<String>,
    /// Roles granted to this identity.
    pub roles: Vec<Role>,
}

/// The full RBAC policy loaded from `rbac.toml`.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RbacPolicy {
    pub identities: Vec<RbacIdentityEntry>,
}

impl RbacPolicy {
    /// Load from a TOML file.
    pub fn load(path: &Path) -> std::io::Result<Self> {
        let s = std::fs::read_to_string(path)?;
        toml::from_str(&s).map_err(|e| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("rbac.toml parse: {e}"),
            )
        })
    }

    /// Returns the set of roles granted to `identity` based on this policy.
    /// An identity matches an entry if:
    ///   - The entry has a `cn` and it case-insensitively matches the cert CN, AND
    ///   - The entry has a `fingerprint` and it exactly matches the cert fingerprint.
    /// If only one of cn/fingerprint is present in the entry, only that field is checked.
    pub fn roles_for(&self, identity: &ClientIdentity) -> HashSet<Role> {
        let mut result = HashSet::new();
        for entry in &self.identities {
            let cn_ok = match (&entry.cn, &identity.cn) {
                (Some(ecn), Some(icn)) => ecn.to_lowercase() == icn.to_lowercase(),
                (Some(_), None) => false, // entry requires CN but cert has none
                (None, _) => true,        // entry doesn't restrict by CN
            };
            let fp_ok = match (&entry.fingerprint, &identity.fingerprint) {
                (Some(efp), Some(ifp)) => efp == ifp,
                (Some(_), None) => false,
                (None, _) => true,
            };
            if cn_ok && fp_ok {
                for role in &entry.roles {
                    result.insert(role.clone());
                }
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

// ── Runtime RBAC checker ──────────────────────────────────────────────────

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
    pub fn from_file(path: &Path) -> std::io::Result<Self> {
        let policy = RbacPolicy::load(path)?;
        Ok(Self {
            policy: parking_lot::RwLock::new(policy),
            path: Some(path.to_path_buf()),
        })
    }

    /// Hot-reload the policy from disk.
    pub fn reload(&self) -> std::io::Result<()> {
        if let Some(p) = &self.path {
            let new = RbacPolicy::load(p)?;
            *self.policy.write() = new;
        }
        Ok(())
    }

    /// Replace the in-memory policy directly (useful for tests and runtime reload without disk).
    pub fn reload_policy(&self, new_policy: RbacPolicy) {
        *self.policy.write() = new_policy;
    }

    /// Returns the reason for denial, or `Ok(roles)` if access is granted.
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

// ── Sample RBAC config generator ─────────────────────────────────────────

/// Write a sample `rbac.toml` to `path` for new deployments.
pub fn write_sample_rbac(path: &Path) -> std::io::Result<()> {
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
    std::fs::write(path, sample)
}

// ── Tests ─────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

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
            fingerprint: Some("00:00".into()), // wrong fingerprint
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
        let result = checker.check(&stranger(), "/admin/status");
        assert!(result.is_err());
        let denial = result.unwrap_err();
        assert_eq!(denial.required, Role::Auditor);
    }
}
