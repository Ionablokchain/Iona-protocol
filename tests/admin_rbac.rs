//! Integration tests for Admin RBAC + mTLS identity enforcement.
//!
//! # What this file covers
//!
//! | Test | Contract |
//! |------|----------|
//! | A1  | Identity with the exact required role is allowed |
//! | A2  | Identity with an insufficient role is denied |
//! | A3  | Unknown identity (no RBAC entry) is denied at every endpoint |
//! | A4  | Anonymous identity is denied under a strict policy |
//! | A5  | Fingerprint mismatch, missing CN, or missing FP cause denial |
//! | A6  | Maintainer subsumes Operator and Auditor |
//! | A7  | Operator subsumes Auditor but not Maintainer |
//! | A8  | Hot-reload takes effect without restart |
//! | A9  | Unknown endpoints require Maintainer |
//! | A10 | `Display` impls are stable |
//! | A11 | Multi-role identity has exactly its declared roles |
//! | A12 | Static endpoint → role map is correct |
//! | A13 | Empty policy denies all |
//! | A14 | CN matching is case-sensitive |
//! | A15 | Fingerprint matching is case-insensitive (per module doc) |
//! | A16 | Policy layer *can* allow anonymous if a matching entry is present |
//!
//! # Not tested here
//!
//! - **mTLS handshake** (`require_mtls = true` rejects connections without a
//!   client cert). Tested in `tests/mtls_handshake.rs` and in the
//!   `rpc::server` module.
//! - **X.509 parsing** (CN extraction, fingerprint canonicalization). Tested
//!   in `src/crypto/x509.rs`.
//! - **Config-layer dev-mode bypass** (`require_mtls = false`). Tested in
//!   `tests/rbac_config.rs`; the RBAC *policy* layer knows nothing about
//!   mTLS — it only sees a `ClientIdentity` that has already been populated
//!   (or left empty) by the TLS layer.
//! - **Role hierarchy implementation** (`Role::subsumes`, `PartialOrd`).
//!   A6/A7 test the *observable* behavior; the ordering itself is a unit
//!   test in `src/rpc/rbac.rs`.
//!
//! # Why A4 tests denial, not bypass
//!
//! A4's original summary claimed "dev mode → anonymous passes auditor
//! check". That conflates two layers. The *config layer* (`require_mtls`)
//! decides whether a TLS handshake is allowed without a client cert. The
//! *policy layer* (this file) decides what a `ClientIdentity` is allowed
//! to do once it exists. A4 tests the policy layer: with a strict policy
//! that has no anonymous entry, an empty `ClientIdentity` is denied. A16
//! tests the complementary case: with a policy that *does* have an
//! anonymous entry, an empty `ClientIdentity` is allowed. Dev-mode bypass
//! is orthogonal and tested separately.

use iona::rpc::rbac::{
    required_role, ClientIdentity, RbacChecker, RbacDenial, RbacPolicy, Role,
};
use std::sync::LazyLock;

// -----------------------------------------------------------------------------
// Standard endpoints used across tests
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
// Test fixtures
// -----------------------------------------------------------------------------

/// Parsed once per test binary; parsing TOML 40+ times is wasted work.
///
/// `LazyLock` requires Rust 1.80+, matching the crate's `rust-version = "1.81"`.
static SAMPLE_POLICY_TOML: &str = r#"
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
"#;

static SAMPLE_POLICY: LazyLock<RbacPolicy> =
    LazyLock::new(|| toml::from_str(SAMPLE_POLICY_TOML).expect("parse sample policy"));

fn sample_policy() -> RbacPolicy {
    SAMPLE_POLICY.clone()
}

/// A policy with a single anonymous identity. Used by A16 to prove the
/// policy layer *can* allow anonymous if configured to.
static ANONYMOUS_POLICY_TOML: &str = r#"
# Dev-mode policy: an entry with cn = "" matches a ClientIdentity with
# `cn = None`, so an anonymous client receives the declared roles.
[[identities]]
cn    = ""
roles = ["auditor"]
"#;

// ── Identity fixtures ────────────────────────────────────────────────────

fn alice() -> ClientIdentity {
    ClientIdentity {
        cn: Some("alice-operator".into()),
        fingerprint: None,
    }
}

fn bob() -> ClientIdentity {
    ClientIdentity {
        cn: Some("bob-auditor".into()),
        fingerprint: None,
    }
}

fn carol() -> ClientIdentity {
    ClientIdentity {
        cn: Some("carol-maintainer".into()),
        fingerprint: Some("AA:BB:CC:DD".into()),
    }
}

fn dave() -> ClientIdentity {
    ClientIdentity {
        cn: Some("dave-multi".into()),
        fingerprint: None,
    }
}

fn nobody() -> ClientIdentity {
    ClientIdentity {
        cn: Some("unknown-hacker".into()),
        fingerprint: None,
    }
}

fn anonymous() -> ClientIdentity {
    ClientIdentity {
        cn: None,
        fingerprint: None,
    }
}

fn identity_with_cn(cn: &str) -> ClientIdentity {
    ClientIdentity {
        cn: Some(cn.to_string()),
        fingerprint: None,
    }
}

fn identity_with_cn_and_fp(cn: &str, fp: &str) -> ClientIdentity {
    ClientIdentity {
        cn: Some(cn.to_string()),
        fingerprint: Some(fp.to_string()),
    }
}

// ── Assertion helpers ────────────────────────────────────────────────────
//
// Each macro evaluates the check **exactly once** and captures the result
// before asserting. The previous macros called `check()` twice — once for
// the assertion and once for the error message — so the diagnostic could
// come from a different invocation than the one that failed.

/// Assert that `checker.check(identity, endpoint)` returns `Ok(())`.
macro_rules! assert_allowed {
    ($checker:expr, $identity:expr, $endpoint:expr, $msg:expr) => {{
        let result = $checker.check(&$identity, $endpoint);
        assert!(
            result.is_ok(),
            "{} — expected ALLOWED but was DENIED: {:?}",
            $msg,
            result.err()
        );
    }};
}

/// Assert that `checker.check(identity, endpoint)` returns `Err(_)`.
macro_rules! assert_denied {
    ($checker:expr, $identity:expr, $endpoint:expr, $msg:expr) => {{
        let result = $checker.check(&$identity, $endpoint);
        assert!(
            result.is_err(),
            "{} — expected DENIED but was ALLOWED",
            $msg
        );
    }};
}

/// Assert that `checker.check(identity, endpoint)` returns `Err` with the
/// expected required role.
#[track_caller]
fn assert_denied_with_role(
    checker: &RbacChecker,
    identity: &ClientIdentity,
    endpoint: &str,
    expected: Role,
) {
    let result = checker.check(identity, endpoint);
    match result {
        Ok(()) => panic!(
            "expected denial for {} on {}, got allowed",
            identity, endpoint
        ),
        Err(denial) => assert_eq!(
            denial.required, expected,
            "wrong required role in denial for {} on {}",
            identity, endpoint
        ),
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// A1 — Correct role is allowed
// ═══════════════════════════════════════════════════════════════════════════════

#[test]
fn a1_operator_allowed_on_operator_role() {
    let policy = sample_policy();
    assert!(
        policy.is_allowed(&alice(), &Role::Operator),
        "alice (operator) must pass Operator check"
    );
}

#[test]
fn a1_auditor_allowed_on_auditor_role() {
    let policy = sample_policy();
    assert!(
        policy.is_allowed(&bob(), &Role::Auditor),
        "bob (auditor) must pass Auditor check"
    );
}

#[test]
fn a1_maintainer_allowed_on_maintainer_role() {
    let policy = sample_policy();
    assert!(
        policy.is_allowed(&carol(), &Role::Maintainer),
        "carol (maintainer + correct fp) must pass Maintainer check"
    );
}

#[test]
fn a1_checker_allows_operator_on_operator_endpoint() {
    let checker = RbacChecker::new(sample_policy());
    assert_allowed!(
        checker,
        alice(),
        ENDPOINT_SNAPSHOT,
        "alice should be allowed on snapshot endpoint"
    );
}

#[test]
fn a1_checker_allows_auditor_on_auditor_endpoint() {
    let checker = RbacChecker::new(sample_policy());
    assert_allowed!(
        checker,
        bob(),
        ENDPOINT_STATUS,
        "bob should be allowed on status endpoint"
    );
}

#[test]
fn a1_checker_allows_maintainer_on_all_endpoints() {
    let checker = RbacChecker::new(sample_policy());
    // Maintainer subsumes every lower role (A6 also tests this), so a
    // maintainer must pass every endpoint regardless of its required role.
    assert_allowed!(checker, carol(), ENDPOINT_SNAPSHOT, "carol on operator endpoint");
    assert_allowed!(checker, carol(), ENDPOINT_STATUS, "carol on auditor endpoint");
    assert_allowed!(checker, carol(), ENDPOINT_KEY_ROTATE, "carol on maintainer endpoint");
}

// ═══════════════════════════════════════════════════════════════════════════════
// A2 — Insufficient role is denied
//
// Note: A2 tests exercise two APIs. `is_allowed(&id, &role)` is the policy
// API (returns `bool`); `checker.check(&id, endpoint)` is the endpoint API
// (returns `Result`). Both must agree: if `is_allowed` is false, `check`
// must return `Err` for every endpoint that requires that role.
// ═══════════════════════════════════════════════════════════════════════════════

#[test]
fn a2_auditor_denied_operator_role() {
    let policy = sample_policy();
    assert!(
        !policy.is_allowed(&bob(), &Role::Operator),
        "bob (auditor) must NOT pass Operator check"
    );
}

#[test]
fn a2_operator_denied_maintainer_role() {
    let policy = sample_policy();
    assert!(
        !policy.is_allowed(&alice(), &Role::Maintainer),
        "alice (operator) must NOT pass Maintainer check"
    );
}

#[test]
fn a2_auditor_denied_maintainer_role() {
    let policy = sample_policy();
    assert!(
        !policy.is_allowed(&bob(), &Role::Maintainer),
        "bob (auditor) must NOT pass Maintainer check"
    );
}

#[test]
fn a2_checker_denies_auditor_on_operator_endpoint() {
    let checker = RbacChecker::new(sample_policy());
    assert_denied_with_role(&checker, &bob(), ENDPOINT_SNAPSHOT, Role::Operator);
}

#[test]
fn a2_checker_denies_operator_on_maintainer_endpoint() {
    let checker = RbacChecker::new(sample_policy());
    assert_denied_with_role(&checker, &alice(), ENDPOINT_KEY_ROTATE, Role::Maintainer);
}

// ═══════════════════════════════════════════════════════════════════════════════
// A3 — Unknown identity denied
// ═══════════════════════════════════════════════════════════════════════════════

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
    assert_denied_with_role(&checker, &nobody(), ENDPOINT_STATUS, Role::Auditor);
}

#[test]
fn a3_unknown_denied_on_all_endpoints() {
    let checker = RbacChecker::new(sample_policy());
    for endpoint in [
        ENDPOINT_STATUS,
        ENDPOINT_AUDIT,
        ENDPOINT_SNAPSHOT,
        ENDPOINT_KEY_ROTATE,
        ENDPOINT_UNKNOWN,
    ] {
        assert_denied!(
            checker,
            nobody(),
            endpoint,
            format!("unknown must be denied on {endpoint}")
        );
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// A4 — Anonymous identity is denied under a strict policy
//
// The RBAC *policy* layer has no anonymous entry in `sample_policy()`, so an
// empty `ClientIdentity` gets no roles. Dev-mode bypass (`require_mtls =
// false`) is a **config-layer** feature and is tested in
// `tests/rbac_config.rs`; A16 below covers the complementary policy-layer
// case (a policy that *does* allow anonymous).
// ═══════════════════════════════════════════════════════════════════════════════

#[test]
fn a4_anonymous_identity_has_no_roles_in_strict_policy() {
    let policy = sample_policy();
    assert!(
        policy.roles_for(&anonymous()).is_empty(),
        "anonymous identity must get zero roles from a strict policy"
    );
}

#[test]
fn a4_anonymous_denied_on_all_endpoints_with_strict_policy() {
    let checker = RbacChecker::new(sample_policy());
    for endpoint in [ENDPOINT_STATUS, ENDPOINT_SNAPSHOT, ENDPOINT_KEY_ROTATE] {
        assert_denied!(
            checker,
            anonymous(),
            endpoint,
            format!("anonymous must be denied on {endpoint} under strict policy")
        );
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// A5 — Fingerprint / CN matching
//
// The policy entry for carol requires *both* a matching CN *and* a matching
// fingerprint. Any of the three following conditions must deny:
//   - wrong fingerprint (CN matches)
//   - missing fingerprint (CN matches)
//   - missing CN (fingerprint matches)
// ═══════════════════════════════════════════════════════════════════════════════

#[test]
fn a5_wrong_fingerprint_denied_despite_matching_cn() {
    let policy = sample_policy();
    let bad_fp = identity_with_cn_and_fp("carol-maintainer", "00:00:00:00");
    assert!(
        policy.roles_for(&bad_fp).is_empty(),
        "correct CN but wrong fingerprint must be denied"
    );
}

#[test]
fn a5_missing_fingerprint_denied_despite_matching_cn() {
    let policy = sample_policy();
    let no_fp = identity_with_cn("carol-maintainer");
    assert!(
        policy.roles_for(&no_fp).is_empty(),
        "missing fingerprint must not match an entry that requires one"
    );
}

#[test]
fn a5_missing_cn_denied_despite_matching_fingerprint() {
    let policy = sample_policy();
    let fp_only = ClientIdentity {
        cn: None,
        fingerprint: Some("AA:BB:CC:DD".into()),
    };
    assert!(
        policy.roles_for(&fp_only).is_empty(),
        "fingerprint alone must not match an entry that also requires a CN"
    );
}

#[test]
fn a5_correct_cn_and_fp_allowed() {
    let policy = sample_policy();
    assert!(
        policy.is_allowed(&carol(), &Role::Maintainer),
        "carol with the exact CN and FP must be allowed"
    );
}

// ═══════════════════════════════════════════════════════════════════════════════
// A6 — Maintainer subsumes Operator and Auditor
// ═══════════════════════════════════════════════════════════════════════════════

#[test]
fn a6_maintainer_passes_operator_check() {
    let policy = sample_policy();
    assert!(
        policy.is_allowed(&carol(), &Role::Operator),
        "maintainer must subsume operator"
    );
}

#[test]
fn a6_maintainer_passes_auditor_check() {
    let policy = sample_policy();
    assert!(
        policy.is_allowed(&carol(), &Role::Auditor),
        "maintainer must subsume auditor"
    );
}

// ═══════════════════════════════════════════════════════════════════════════════
// A7 — Operator subsumes Auditor but not Maintainer
// ═══════════════════════════════════════════════════════════════════════════════

#[test]
fn a7_operator_passes_auditor_check() {
    let policy = sample_policy();
    assert!(
        policy.is_allowed(&alice(), &Role::Auditor),
        "operator must subsume auditor"
    );
}

#[test]
fn a7_operator_fails_maintainer_check() {
    let policy = sample_policy();
    assert!(
        !policy.is_allowed(&alice(), &Role::Maintainer),
        "operator must NOT subsume maintainer"
    );
}

// ═══════════════════════════════════════════════════════════════════════════════
// A8 — Hot-reload
// ═══════════════════════════════════════════════════════════════════════════════

#[test]
fn a8_hot_reload_revokes_role() {
    let checker = RbacChecker::new(sample_policy());
    assert_allowed!(
        checker,
        alice(),
        ENDPOINT_SNAPSHOT,
        "alice should be operator before reload"
    );

    let demoted: RbacPolicy = toml::from_str(
        r#"
[[identities]]
cn    = "alice-operator"
roles = ["auditor"]
"#,
    )
    .unwrap();
    checker.reload_policy(demoted);

    assert_denied_with_role(&checker, &alice(), ENDPOINT_SNAPSHOT, Role::Operator);
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
    let eve = identity_with_cn("eve");

    assert_denied!(
        checker,
        eve,
        ENDPOINT_SNAPSHOT,
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

    assert_allowed!(
        checker,
        eve,
        ENDPOINT_SNAPSHOT,
        "eve must be allowed operator endpoint after promotion"
    );
}

#[test]
fn a8_hot_reload_clears_all() {
    let checker = RbacChecker::new(sample_policy());
    assert_allowed!(checker, alice(), ENDPOINT_SNAPSHOT, "alice allowed before clear");

    checker.reload_policy(RbacPolicy::default());

    assert_denied_with_role(&checker, &alice(), ENDPOINT_SNAPSHOT, Role::Operator);
    assert_denied_with_role(&checker, &bob(), ENDPOINT_STATUS, Role::Auditor);
    assert_denied_with_role(&checker, &carol(), ENDPOINT_KEY_ROTATE, Role::Maintainer);
}

// ═══════════════════════════════════════════════════════════════════════════════
// A9 — Unknown endpoints require Maintainer
// ═══════════════════════════════════════════════════════════════════════════════

#[test]
fn a9_unknown_admin_endpoint_requires_maintainer() {
    assert_eq!(
        required_role(ENDPOINT_UNKNOWN),
        Role::Maintainer,
        "unknown endpoints must default to the most restrictive role"
    );
}

#[test]
fn a9_operator_denied_on_unknown_endpoint() {
    let checker = RbacChecker::new(sample_policy());
    assert_denied_with_role(&checker, &alice(), ENDPOINT_UNKNOWN, Role::Maintainer);
}

#[test]
fn a9_maintainer_allowed_on_unknown_endpoint() {
    let checker = RbacChecker::new(sample_policy());
    assert_allowed!(
        checker,
        carol(),
        ENDPOINT_UNKNOWN,
        "maintainer must be allowed on unknown endpoints"
    );
}

// ═══════════════════════════════════════════════════════════════════════════════
// A10 — Display formatting
// ═══════════════════════════════════════════════════════════════════════════════

#[test]
fn a10_client_identity_display_cn_only() {
    assert_eq!(
        format!("{}", identity_with_cn("ops-alice")),
        "CN=ops-alice"
    );
}

#[test]
fn a10_client_identity_display_cn_and_fingerprint() {
    let display = format!("{}", identity_with_cn_and_fp("node-maint", "AA:BB:CC"));
    assert!(display.contains("CN=node-maint"), "display must include CN");
    assert!(display.contains("fp=AA:BB:CC"), "display must include fingerprint");
}

#[test]
fn a10_client_identity_display_anonymous() {
    assert_eq!(format!("{}", anonymous()), "<unknown>");
}

#[test]
fn a10_client_identity_display_fingerprint_only() {
    let id = ClientIdentity {
        cn: None,
        fingerprint: Some("AA:BB:CC".into()),
    };
    let display = format!("{id}");
    assert!(display.contains("fp=AA:BB:CC"), "display must include fingerprint");
}

#[test]
fn a10_rbac_denial_display() {
    let checker = RbacChecker::new(sample_policy());
    let denial: RbacDenial = checker.check(&bob(), ENDPOINT_SNAPSHOT).unwrap_err();
    let s = format!("{denial}");
    assert!(s.contains("RBAC denied"), "denial must say 'RBAC denied': {s}");
    assert!(s.contains("bob-auditor"), "denial must name the identity: {s}");
    assert!(s.contains(ENDPOINT_SNAPSHOT), "denial must name the endpoint: {s}");
    assert!(s.contains("Operator"), "denial must name the required role: {s}");
}

// ═══════════════════════════════════════════════════════════════════════════════
// A11 — Multi-role identity
// ═══════════════════════════════════════════════════════════════════════════════

#[test]
fn a11_dave_multi_role_has_both_declared_roles() {
    let policy = sample_policy();
    let roles = policy.roles_for(&dave());
    assert!(roles.contains(&Role::Operator), "dave must have Operator");
    assert!(roles.contains(&Role::Auditor), "dave must have Auditor");
    assert_eq!(roles.len(), 2, "dave must have exactly the 2 declared roles");
}

#[test]
fn a11_dave_multi_role_still_denied_maintainer() {
    let policy = sample_policy();
    assert!(
        !policy.is_allowed(&dave(), &Role::Maintainer),
        "dave (operator + auditor) must not pass maintainer"
    );
}

// ═══════════════════════════════════════════════════════════════════════════════
// A12 — Endpoint → role map (static contract)
//
// These are pure `required_role` lookups: they document the endpoint
// classification. A9 covers the checker-level consequence.
// ═══════════════════════════════════════════════════════════════════════════════

#[test]
fn a12_endpoint_map_read_only_is_auditor() {
    assert_eq!(required_role(ENDPOINT_STATUS), Role::Auditor);
    assert_eq!(required_role(ENDPOINT_AUDIT), Role::Auditor);
    assert_eq!(required_role(ENDPOINT_METRICS), Role::Auditor);
}

#[test]
fn a12_endpoint_map_control_is_operator() {
    assert_eq!(required_role(ENDPOINT_SNAPSHOT), Role::Operator);
    assert_eq!(required_role(ENDPOINT_PEER_KICK), Role::Operator);
    assert_eq!(required_role(ENDPOINT_CONFIG_RELOAD), Role::Operator);
    assert_eq!(required_role(ENDPOINT_MEMPOOL_FLUSH), Role::Operator);
}

#[test]
fn a12_endpoint_map_destructive_is_maintainer() {
    assert_eq!(required_role(ENDPOINT_KEY_ROTATE), Role::Maintainer);
    assert_eq!(required_role(ENDPOINT_UPGRADE_TRIGGER), Role::Maintainer);
    assert_eq!(required_role("/admin/reset-chain"), Role::Maintainer);
    assert_eq!(required_role("/admin/schema-migrate"), Role::Maintainer);
}

// ═══════════════════════════════════════════════════════════════════════════════
// A13 — Empty policy denies all
// ═══════════════════════════════════════════════════════════════════════════════

#[test]
fn a13_empty_policy_denies_all() {
    let checker = RbacChecker::new(RbacPolicy::default());

    assert_denied!(checker, alice(), ENDPOINT_STATUS, "alice denied with empty policy");
    assert_denied!(checker, bob(), ENDPOINT_SNAPSHOT, "bob denied with empty policy");
    assert_denied!(checker, carol(), ENDPOINT_KEY_ROTATE, "carol denied with empty policy");
    assert_denied!(checker, anonymous(), ENDPOINT_STATUS, "anonymous denied with empty policy");
}

// ═══════════════════════════════════════════════════════════════════════════════
// A14 — CN matching is case-sensitive
// ═══════════════════════════════════════════════════════════════════════════════

#[test]
fn a14_cn_matching_is_case_sensitive() {
    let checker = RbacChecker::new(sample_policy());

    // Policy entry is "alice-operator" (all lowercase).
    assert_allowed!(
        checker,
        identity_with_cn("alice-operator"),
        ENDPOINT_SNAPSHOT,
        "exact-case CN must match"
    );

    // Any different case must NOT match.
    for cn in ["Alice-Operator", "ALICE-OPERATOR", "alice-Operator"] {
        assert_denied!(
            checker,
            identity_with_cn(cn),
            ENDPOINT_SNAPSHOT,
            format!("case-changed CN {cn:?} must not match")
        );
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// A15 — Fingerprint matching is case-insensitive (per module doc)
//
// The module doc states that fingerprints are compared case-insensitively.
// This test asserts that behavior. If it fails, the implementation is
// case-sensitive and either the code must be fixed (normalize on both sides
// before comparison) or the module doc must be updated to say the comparison
// is case-sensitive.
// ═══════════════════════════════════════════════════════════════════════════════

#[test]
fn a15_fingerprint_matching_is_case_insensitive() {
    let checker = RbacChecker::new(sample_policy());

    // Policy entry declares "AA:BB:CC:DD".
    // All case variants must be accepted.
    for fp in ["AA:BB:CC:DD", "aa:bb:cc:dd", "Aa:Bb:Cc:Dd"] {
        assert_allowed!(
            checker,
            identity_with_cn_and_fp("carol-maintainer", fp),
            ENDPOINT_KEY_ROTATE,
            format!("case-variant fingerprint {fp:?} must match")
        );
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// A16 — Policy layer *can* allow anonymous (complement to A4)
//
// A4 shows that a strict policy with no anonymous entry denies anonymous
// clients. A16 shows that the *policy layer* itself has no hardcoded rule
// against anonymous identities: if a policy entry matches, the anonymous
// client is allowed. Dev-mode bypass (`require_mtls = false`) lives in the
// config layer and is tested in `tests/rbac_config.rs`; this test covers
// only the policy layer's view of the world.
// ═══════════════════════════════════════════════════════════════════════════════

#[test]
fn a16_policy_with_anonymous_entry_allows_anonymous() {
    let policy: RbacPolicy = toml::from_str(ANONYMOUS_POLICY_TOML)
        .expect("parse anonymous policy");
    let checker = RbacChecker::new(policy);

    assert_allowed!(
        checker,
        anonymous(),
        ENDPOINT_STATUS,
        "anonymous must be allowed on auditor endpoint when policy grants it"
    );

    // The anonymous client should *not* inherit roles above Auditor.
    assert_denied!(
        checker,
        anonymous(),
        ENDPOINT_SNAPSHOT,
        "anonymous must still be denied on operator endpoint"
    );
}
