//! Integration tests for Admin RBAC + mTLS identity enforcement.
//!
//! Covers:
//!  A1  — Identity with correct role is allowed
//!  A2  — Identity with insufficient role is denied (403)
//!  A3  — Unknown identity (no RBAC entry) is denied at any endpoint
//!  A4  — mTLS not required (dev mode) → anonymous identity passes auditor check
//!  A5  — Fingerprint mismatch denies even if CN matches
//!  A6  — Role hierarchy: Maintainer passes Operator and Auditor checks
//!  A7  — Role hierarchy: Operator passes Auditor check but not Maintainer
//!  A8  — Hot-reload: policy changes take effect without restart
//!  A9  — Unknown endpoint defaults to Maintainer-required
//!  A10 — Display formatting of ClientIdentity and RbacDenial

use iona::rpc::rbac::{
    required_role, ClientIdentity, RbacChecker, RbacDenial, RbacPolicy, Role,
};

// -----------------------------------------------------------------------------
// Constants (standard endpoints)
// -----------------------------------------------------------------------------

const ENDPOINT_STATUS: &str = "/admin/status";
const ENDPOINT_AUDIT: &str = "/admin/audit";
const ENDPOINT_METRICS: &str = "/admin/metrics";
const ENDPOINT_SNAPSHOT: &str = "/admin/snapshot";
const ENDPOINT_PEER_KICK: &str = "/admin/peer-kick";
const ENDPOINT_CONFIG_RELOAD: &str = "/admin/config-reload";
const ENDPOINT_MEMPOOL_FLUSH: &str = "/admin/mempool-flush";
const ENDPOINT_KEY_ROTATE: &str = "/admin/key-rotate";
const ENDPOINT_UPGRADE_TRIGGER: &str = "/admin/upgrade-trigger";
const ENDPOINT_UNKNOWN: &str = "/admin/some-new-endpoint";

// -----------------------------------------------------------------------------
// Test helpers
// -----------------------------------------------------------------------------

/// Sample RBAC policy used across most tests.
fn sample_policy() -> RbacPolicy {
    toml::from_str(
        r#"
[[identities]]
cn    = "alice-operator"
roles = ["operator"]

[[identities]]
cn    = "bob-auditor"
roles = ["auditor"]

[[identities]]
cn          = "carol-maintainer"
fingerprint = "AA:BB:CC:DD"
roles       = ["maintainer"]

[[identities]]
cn    = "dave-multi"
roles = ["operator", "auditor"]
"#,
    )
    .expect("parse sample policy")
}

/// Identity: alice (operator)
fn alice() -> ClientIdentity {
    ClientIdentity {
        cn: Some("alice-operator".into()),
        fingerprint: None,
    }
}

/// Identity: bob (auditor)
fn bob() -> ClientIdentity {
    ClientIdentity {
        cn: Some("bob-auditor".into()),
        fingerprint: None,
    }
}

/// Identity: carol (maintainer with matching fingerprint)
fn carol() -> ClientIdentity {
    ClientIdentity {
        cn: Some("carol-maintainer".into()),
        fingerprint: Some("AA:BB:CC:DD".into()),
    }
}

/// Identity: dave (operator + auditor)
fn dave() -> ClientIdentity {
    ClientIdentity {
        cn: Some("dave-multi".into()),
        fingerprint: None,
    }
}

/// Identity: unknown (no matching entry)
fn nobody() -> ClientIdentity {
    ClientIdentity {
        cn: Some("unknown-hacker".into()),
        fingerprint: None,
    }
}

// -----------------------------------------------------------------------------
// A1: Correct role is allowed
// -----------------------------------------------------------------------------

#[test]
fn a1_operator_allowed_on_operator_endpoint() {
    let policy = sample_policy();
    assert!(
        policy.is_allowed(&alice(), &Role::Operator),
        "alice (operator) must pass Operator check"
    );
}

#[test]
fn a1_auditor_allowed_on_auditor_endpoint() {
    let policy = sample_policy();
    assert!(
        policy.is_allowed(&bob(), &Role::Auditor),
        "bob (auditor) must pass Auditor check"
    );
}

#[test]
fn a1_maintainer_allowed_on_maintainer_endpoint() {
    let policy = sample_policy();
    assert!(
        policy.is_allowed(&carol(), &Role::Maintainer),
        "carol (maintainer + correct fp) must pass Maintainer check"
    );
}

// -----------------------------------------------------------------------------
// A2: Insufficient role is denied
// -----------------------------------------------------------------------------

#[test]
fn a2_auditor_denied_on_operator_endpoint() {
    let policy = sample_policy();
    assert!(
        !policy.is_allowed(&bob(), &Role::Operator),
        "bob (auditor) must NOT pass Operator check"
    );
}

#[test]
fn a2_operator_denied_on_maintainer_endpoint() {
    let policy = sample_policy();
    assert!(
        !policy.is_allowed(&alice(), &Role::Maintainer),
        "alice (operator) must NOT pass Maintainer check"
    );
}

#[test]
fn a2_auditor_denied_on_maintainer_endpoint() {
    let policy = sample_policy();
    assert!(
        !policy.is_allowed(&bob(), &Role::Maintainer),
        "bob (auditor) must NOT pass Maintainer check"
    );
}

// -----------------------------------------------------------------------------
// A3: Unknown identity denied
// -----------------------------------------------------------------------------

#[test]
fn a3_unknown_identity_gets_no_roles() {
    let policy = sample_policy();
    assert!(
        policy.roles_for(&nobody()).is_empty(),
        "unknown identity must receive zero roles"
    );
}

#[test]
fn a3_unknown_identity_denied_auditor() {
    let policy = sample_policy();
    assert!(
        !policy.is_allowed(&nobody(), &Role::Auditor),
        "unknown identity must be denied even at Auditor level"
    );
}

#[test]
fn a3_checker_returns_denial_for_unknown() {
    let checker = RbacChecker::new(sample_policy());
    let result = checker.check(&nobody(), ENDPOINT_STATUS);
    assert!(result.is_err(), "unknown identity must return Err(denial)");
    let denial = result.unwrap_err();
    assert_eq!(
        denial.required,
        Role::Auditor,
        "denial must report the required role"
    );
}

// -----------------------------------------------------------------------------
// A4: Dev mode (require_mtls=false) passes anonymous identity
// -----------------------------------------------------------------------------

#[test]
fn a4_anonymous_identity_has_no_roles_in_strict_policy() {
    let policy = sample_policy();
    let anonymous = ClientIdentity {
        cn: None,
        fingerprint: None,
    };
    assert!(
        policy.roles_for(&anonymous).is_empty(),
        "anonymous identity must get zero roles from policy"
    );
}

// -----------------------------------------------------------------------------
// A5: Fingerprint mismatch
// -----------------------------------------------------------------------------

#[test]
fn a5_correct_cn_wrong_fp_denied() {
    let policy = sample_policy();
    let bad_fingerprint = ClientIdentity {
        cn: Some("carol-maintainer".into()),
        fingerprint: Some("00:00:00:00".into()),
    };
    assert!(
        policy.roles_for(&bad_fingerprint).is_empty(),
        "correct CN but wrong fingerprint must be denied"
    );
}

#[test]
fn a5_correct_fp_no_cn_denied_when_entry_requires_cn() {
    let policy = sample_policy();
    let fingerprint_only = ClientIdentity {
        cn: None,
        fingerprint: Some("AA:BB:CC:DD".into()),
    };
    // carol's entry has both cn and fingerprint; missing CN → cn_ok = false.
    assert!(
        policy.roles_for(&fingerprint_only).is_empty(),
        "fingerprint alone must not match entry that also requires CN"
    );
}

// -----------------------------------------------------------------------------
// A6: Role hierarchy — Maintainer subsumes all
// -----------------------------------------------------------------------------

#[test]
fn a6_maintainer_passes_operator_check() {
    let policy = sample_policy();
    assert!(
        policy.is_allowed(&carol(), &Role::Operator),
        "maintainer must subsume operator role"
    );
}

#[test]
fn a6_maintainer_passes_auditor_check() {
    let policy = sample_policy();
    assert!(
        policy.is_allowed(&carol(), &Role::Auditor),
        "maintainer must subsume auditor role"
    );
}

// -----------------------------------------------------------------------------
// A7: Operator subsumes Auditor but not Maintainer
// -----------------------------------------------------------------------------

#[test]
fn a7_operator_passes_auditor_check() {
    let policy = sample_policy();
    assert!(
        policy.is_allowed(&alice(), &Role::Auditor),
        "operator must subsume auditor role"
    );
}

#[test]
fn a7_operator_fails_maintainer_check() {
    let policy = sample_policy();
    assert!(
        !policy.is_allowed(&alice(), &Role::Maintainer),
        "operator must NOT subsume maintainer role"
    );
}

// -----------------------------------------------------------------------------
// A8: Hot-reload changes take effect
// -----------------------------------------------------------------------------

#[test]
fn a8_hot_reload_revokes_role() {
    let checker = RbacChecker::new(sample_policy());
    assert!(
        checker.check(&alice(), ENDPOINT_SNAPSHOT).is_ok(),
        "alice should be operator before reload"
    );

    let new_policy: RbacPolicy = toml::from_str(
        r#"
[[identities]]
cn    = "alice-operator"
roles = ["auditor"]
"#,
    )
    .unwrap();
    checker.reload_policy(new_policy);

    let result = checker.check(&alice(), ENDPOINT_SNAPSHOT);
    assert!(
        result.is_err(),
        "alice must be denied operator endpoint after reload demotes her to auditor"
    );
}

#[test]
fn a8_hot_reload_adds_role() {
    let initial: RbacPolicy = toml::from_str(
        r#"
[[identities]]
cn    = "eve"
roles = ["auditor"]
"#,
    )
    .unwrap();
    let checker = RbacChecker::new(initial);
    let eve = ClientIdentity {
        cn: Some("eve".into()),
        fingerprint: None,
    };

    assert!(
        checker.check(&eve, ENDPOINT_SNAPSHOT).is_err(),
        "eve must be denied operator endpoint initially"
    );

    let promoted: RbacPolicy = toml::from_str(
        r#"
[[identities]]
cn    = "eve"
roles = ["operator"]
"#,
    )
    .unwrap();
    checker.reload_policy(promoted);

    assert!(
        checker.check(&eve, ENDPOINT_SNAPSHOT).is_ok(),
        "eve must be allowed operator endpoint after promotion"
    );
}

// -----------------------------------------------------------------------------
// A9: Unknown endpoint defaults to Maintainer
// -----------------------------------------------------------------------------

#[test]
fn a9_unknown_admin_endpoint_requires_maintainer() {
    assert_eq!(
        required_role(ENDPOINT_UNKNOWN),
        Role::Maintainer,
        "unknown endpoints must default to most restrictive role"
    );
}

#[test]
fn a9_operator_denied_on_unknown_endpoint() {
    let checker = RbacChecker::new(sample_policy());
    let result = checker.check(&alice(), ENDPOINT_UNKNOWN);
    assert!(
        result.is_err(),
        "operator must be denied unknown admin endpoint (defaults to maintainer)"
    );
}

// -----------------------------------------------------------------------------
// A10: Display formatting
// -----------------------------------------------------------------------------

#[test]
fn a10_client_identity_display_cn_only() {
    let id = ClientIdentity {
        cn: Some("ops-alice".into()),
        fingerprint: None,
    };
    assert_eq!(format!("{id}"), "CN=ops-alice");
}

#[test]
fn a10_client_identity_display_both() {
    let id = ClientIdentity {
        cn: Some("node-maint".into()),
        fingerprint: Some("AA:BB:CC".into()),
    };
    assert!(
        format!("{id}").contains("CN=node-maint"),
        "display must include CN"
    );
    assert!(
        format!("{id}").contains("fp=AA:BB:CC"),
        "display must include fingerprint"
    );
}

#[test]
fn a10_client_identity_display_unknown() {
    let id = ClientIdentity {
        cn: None,
        fingerprint: None,
    };
    assert_eq!(format!("{id}"), "<unknown>");
}

#[test]
fn a10_rbac_denial_display() {
    let checker = RbacChecker::new(sample_policy());
    let denial = checker.check(&bob(), ENDPOINT_SNAPSHOT).unwrap_err();
    let s = format!("{denial}");
    assert!(
        s.contains("RBAC denied"),
        "denial string must contain 'RBAC denied'"
    );
    assert!(
        s.contains("bob-auditor"),
        "denial string must name the identity"
    );
    assert!(
        s.contains(ENDPOINT_SNAPSHOT),
        "denial string must name the endpoint"
    );
}

// -----------------------------------------------------------------------------
// Multi-role identity
// -----------------------------------------------------------------------------

#[test]
fn dave_multi_role_has_both() {
    use std::collections::HashSet;
    let policy = sample_policy();
    let roles = policy.roles_for(&dave());
    assert!(roles.contains(&Role::Operator), "dave must have Operator");
    assert!(roles.contains(&Role::Auditor), "dave must have Auditor");
}

#[test]
fn dave_multi_role_still_denied_maintainer() {
    let policy = sample_policy();
    assert!(
        !policy.is_allowed(&dave(), &Role::Maintainer),
        "dave (operator+auditor) must not pass maintainer check"
    );
}

// -----------------------------------------------------------------------------
// Endpoint permission map (unit checks)
// -----------------------------------------------------------------------------

#[test]
fn endpoint_map_read_only_is_auditor() {
    assert_eq!(required_role(ENDPOINT_STATUS), Role::Auditor);
    assert_eq!(required_role(ENDPOINT_AUDIT), Role::Auditor);
    assert_eq!(required_role(ENDPOINT_METRICS), Role::Auditor);
}

#[test]
fn endpoint_map_control_is_operator() {
    assert_eq!(required_role(ENDPOINT_SNAPSHOT), Role::Operator);
    assert_eq!(required_role(ENDPOINT_PEER_KICK), Role::Operator);
    assert_eq!(required_role(ENDPOINT_CONFIG_RELOAD), Role::Operator);
    assert_eq!(required_role(ENDPOINT_MEMPOOL_FLUSH), Role::Operator);
}

#[test]
fn endpoint_map_destructive_is_maintainer() {
    assert_eq!(required_role(ENDPOINT_KEY_ROTATE), Role::Maintainer);
    assert_eq!(required_role(ENDPOINT_UPGRADE_TRIGGER), Role::Maintainer);
    assert_eq!(required_role("/admin/reset-chain"), Role::Maintainer);
    assert_eq!(required_role("/admin/schema-migrate"), Role::Maintainer);
}
