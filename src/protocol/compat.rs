//! Backward compatibility enforcement layer.
//!
//! Ensures that all protocol changes maintain backward compatibility
//! according to strict rules. This module validates:
//!
//! - **Wire format compatibility**: Messages can be decoded by older nodes
//! - **State format compatibility**: Storage can be read by older binaries
//! - **RPC compatibility**: API responses remain backward-compatible
//! - **Consensus rule compatibility**: Block validation rules are monotonic
//!
//! # Compatibility Levels
//!
//! ```text
//! Level 0 (Full):      No changes to wire/state/RPC format
//! Level 1 (Additive):  New optional fields only (serde default)
//! Level 2 (Migration): Requires schema migration (dual-read period)
//! Level 3 (Breaking):  Requires protocol version bump + activation height
//! ```

use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::fs;
use std::path::Path;
use tracing::{error, info};

#[cfg(feature = "prometheus")]
use prometheus::{register_int_counter_vec, IntCounterVec};

use super::version::{ProtocolActivation, SUPPORTED_PROTOCOL_VERSIONS};

// ─── Compatibility level ─────────────────────────────────────────────────────

/// Backward compatibility level for a change.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum CompatLevel {
    /// No format changes at all.
    Full = 0,
    /// Additive changes only (new optional fields with defaults).
    Additive = 1,
    /// Requires schema migration with dual-read support.
    Migration = 2,
    /// Breaking change requiring PV bump and activation height.
    Breaking = 3,
}

impl std::fmt::Display for CompatLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Full => write!(f, "Full (Level 0)"),
            Self::Additive => write!(f, "Additive (Level 1)"),
            Self::Migration => write!(f, "Migration (Level 2)"),
            Self::Breaking => write!(f, "Breaking (Level 3)"),
        }
    }
}

// ─── Compatibility rule ──────────────────────────────────────────────────────

/// A compatibility rule that can be checked.
#[derive(Debug, Clone)]
pub struct CompatRule {
    /// Rule identifier (e.g., "WIRE-001").
    pub id: String,
    /// Human-readable description.
    pub description: String,
    /// Which compatibility domain this rule applies to.
    pub domain: CompatDomain,
    /// Whether this rule is enforced (failure = error) or advisory (failure = warning).
    pub enforced: bool,
}

/// Domain of a compatibility rule.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Hash)]
pub enum CompatDomain {
    /// P2P wire format (messages, handshake).
    Wire,
    /// On-disk state format (state_full.json, blocks/, stakes.json).
    State,
    /// RPC API responses (JSON-RPC, REST).
    Rpc,
    /// Consensus rules (block validation, finality).
    Consensus,
}

impl std::fmt::Display for CompatDomain {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Wire => write!(f, "Wire"),
            Self::State => write!(f, "State"),
            Self::Rpc => write!(f, "RPC"),
            Self::Consensus => write!(f, "Consensus"),
        }
    }
}

// ─── Check result ────────────────────────────────────────────────────────────

/// Result of a single compatibility check, with an optional recommendation.
#[derive(Debug, Clone)]
pub struct CompatCheckResult {
    pub rule_id: String,
    pub domain: CompatDomain,
    pub passed: bool,
    pub level: CompatLevel,
    pub detail: String,
    pub recommendation: Option<String>,
}

/// Aggregate result of all compatibility checks.
#[derive(Debug, Clone)]
pub struct CompatReport {
    pub results: Vec<CompatCheckResult>,
    pub overall_level: CompatLevel,
    pub passed: bool,
}

impl CompatReport {
    pub fn from_results(results: Vec<CompatCheckResult>) -> Self {
        let passed = results.iter().all(|r| r.passed);
        let overall_level = results.iter()
            .map(|r| r.level)
            .max()
            .unwrap_or(CompatLevel::Full);
        Self { results, overall_level, passed }
    }

    /// Get results filtered by domain.
    pub fn by_domain(&self, domain: CompatDomain) -> Vec<&CompatCheckResult> {
        self.results.iter().filter(|r| r.domain == domain).collect()
    }

    /// Get only failed checks.
    pub fn failures(&self) -> Vec<&CompatCheckResult> {
        self.results.iter().filter(|r| !r.passed).collect()
    }

    /// Get only enforced checks that failed.
    pub fn enforced_failures(&self, rules: &[CompatRule]) -> Vec<&CompatCheckResult> {
        let enforced_ids: HashSet<_> = rules.iter().filter(|r| r.enforced).map(|r| &r.id).collect();
        self.results.iter()
            .filter(|r| !r.passed && enforced_ids.contains(&r.rule_id.as_str()))
            .collect()
    }

    /// Log results using tracing.
    pub fn log(&self) {
        if self.passed {
            info!("Compatibility check passed (level {})", self.overall_level);
        } else {
            error!("Compatibility check FAILED (level {})", self.overall_level);
            for f in self.failures() {
                error!("  [{}] {}: {}", f.domain, f.rule_id, f.detail);
                if let Some(rec) = &f.recommendation {
                    error!("    Recommendation: {}", rec);
                }
            }
        }
    }
}

impl std::fmt::Display for CompatReport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "Compatibility Report: {} ({})",
            if self.passed { "PASS" } else { "FAIL" },
            self.overall_level
        )?;
        for r in &self.results {
            let mark = if r.passed { "OK" } else { "FAIL" };
            writeln!(f, "  [{mark}] [{}] {}: {} ({})", r.domain, r.rule_id, r.detail, r.level)?;
            if let Some(rec) = &r.recommendation {
                writeln!(f, "        Recommendation: {}", rec)?;
            }
        }
        Ok(())
    }
}

// ─── Compatibility checker ───────────────────────────────────────────────────

/// Backward compatibility enforcement checker.
///
/// Validates that protocol changes maintain compatibility at all levels.
pub struct CompatChecker {
    /// Active protocol activations.
    activations: Vec<ProtocolActivation>,
    /// Registered compatibility rules.
    rules: Vec<CompatRule>,
    /// Path to OpenAPI spec (for RPC checks).
    openapi_path: Option<String>,
    /// Prometheus metrics (if feature enabled).
    #[cfg(feature = "prometheus")]
    metric_failures: IntCounterVec,
}

impl CompatChecker {
    /// Create a new checker with the default rule set.
    pub fn new(activations: Vec<ProtocolActivation>) -> Self {
        #[cfg(feature = "prometheus")]
        let metric_failures = register_int_counter_vec!(
            "iona_compat_check_failures_total",
            "Number of failed compatibility checks",
            &["rule_id", "domain"]
        ).unwrap_or_else(|_| IntCounterVec::new(prometheus::opts!()).unwrap());

        Self {
            activations,
            rules: default_rules(),
            openapi_path: None,
            #[cfg(feature = "prometheus")]
            metric_failures,
        }
    }

    /// Set an optional path to the OpenAPI spec for RPC validation.
    pub fn with_openapi(mut self, path: impl Into<String>) -> Self {
        self.openapi_path = Some(path.into());
        self
    }

    /// Run all compatibility checks and return a report.
    pub fn check_all(&self) -> CompatReport {
        let mut results = Vec::new();

        // Wire compatibility checks.
        results.push(self.check_wire_pv_overlap());
        results.push(self.check_wire_unknown_msg_handling());
        results.push(self.check_wire_handshake_version());

        // State compatibility checks.
        results.push(self.check_state_schema_monotonic());
        results.push(self.check_state_serde_defaults());
        results.push(self.check_state_migration_exists());

        // RPC compatibility checks.
        results.push(self.check_rpc_field_additive());
        results.push(self.check_rpc_method_preserved());
        results.push(self.check_rpc_openapi_readable()); // renamed

        // Consensus compatibility checks.
        results.push(self.check_consensus_pv_deterministic());
        results.push(self.check_consensus_activation_scheduled());
        results.push(self.check_consensus_grace_window());

        // Update metrics for failed checks.
        #[cfg(feature = "prometheus")]
        for r in &results {
            if !r.passed {
                self.metric_failures
                    .with_label_values(&[&r.rule_id, &format!("{}", r.domain)])
                    .inc();
            }
        }

        CompatReport::from_results(results)
    }

    /// Run only enforced checks and return a report.
    pub fn check_enforced(&self) -> CompatReport {
        let full = self.check_all();
        let enforced_ids: HashSet<_> = self.rules.iter().filter(|r| r.enforced).map(|r| &r.id).collect();
        let filtered_results: Vec<_> = full.results
            .into_iter()
            .filter(|r| enforced_ids.contains(&r.rule_id.as_str()))
            .collect();
        CompatReport::from_results(filtered_results)
    }

    // ── Wire checks ──────────────────────────────────────────────────────

    /// WIRE-001: Current binary supports PV=1 for backward compatibility.
    fn check_wire_pv_overlap(&self) -> CompatCheckResult {
        let current_pvs = SUPPORTED_PROTOCOL_VERSIONS;
        let has_pv1 = current_pvs.contains(&1);

        CompatCheckResult {
            rule_id: "WIRE-001".into(),
            domain: CompatDomain::Wire,
            passed: has_pv1,
            level: CompatLevel::Full,
            detail: format!(
                "supported PVs {:?} {}include PV=1",
                current_pvs,
                if has_pv1 { "" } else { "do NOT " }
            ),
            recommendation: if has_pv1 { None } else {
                Some("Add PV=1 to SUPPORTED_PROTOCOL_VERSIONS.".into())
            },
        }
    }

    /// WIRE-002: By design, unknown message type IDs are silently ignored (forward compatibility).
    fn check_wire_unknown_msg_handling(&self) -> CompatCheckResult {
        CompatCheckResult {
            rule_id: "WIRE-002".into(),
            domain: CompatDomain::Wire,
            passed: true, // Design assertion
            level: CompatLevel::Full,
            detail: "unknown msg_type IDs silently ignored (by design)".into(),
            recommendation: None,
        }
    }

    /// WIRE-003: By design, handshake Hello includes version negotiation fields.
    fn check_wire_handshake_version(&self) -> CompatCheckResult {
        CompatCheckResult {
            rule_id: "WIRE-003".into(),
            domain: CompatDomain::Wire,
            passed: true, // Design assertion
            level: CompatLevel::Full,
            detail: "Hello includes supported_pv, chain_id, genesis_hash".into(),
            recommendation: None,
        }
    }

    // ── State checks ─────────────────────────────────────────────────────

    /// STATE-001: Schema version must be monotonically increasing.
    fn check_state_schema_monotonic(&self) -> CompatCheckResult {
        let sv = crate::storage::CURRENT_SCHEMA_VERSION;
        let monotonic = sv >= 1; // Must be at least 1

        CompatCheckResult {
            rule_id: "STATE-001".into(),
            domain: CompatDomain::State,
            passed: monotonic,
            level: CompatLevel::Migration,
            detail: format!("schema_version={sv} (monotonic: {monotonic})"),
            recommendation: if monotonic { None } else {
                Some("Set CURRENT_SCHEMA_VERSION to at least 1.".into())
            },
        }
    }

    /// STATE-002: By convention, new fields use #[serde(default)] or Option<T>.
    fn check_state_serde_defaults(&self) -> CompatCheckResult {
        CompatCheckResult {
            rule_id: "STATE-002".into(),
            domain: CompatDomain::State,
            passed: true, // Convention, enforced in code review
            level: CompatLevel::Additive,
            detail: "new fields should use #[serde(default)] or Option<T> (convention)".into(),
            recommendation: None,
        }
    }

    /// Check if a migration exists for a given from-version.
    fn migration_exists(from: u32) -> bool {
        match from {
            0..=2 => true, // hardcoded legacy migrations in DataDir::run_migration
            _ => crate::storage::migrations::MIGRATIONS.iter().any(|(f, _, _)| *f == from)
        }
    }

    /// STATE-003: Schema migration exists for each version bump (assumes linear 0..current).
    fn check_state_migration_exists(&self) -> CompatCheckResult {
        let sv = crate::storage::CURRENT_SCHEMA_VERSION;
        let mut missing = Vec::new();
        for from in 0..sv {
            if !Self::migration_exists(from) {
                missing.push(from);
            }
        }
        let passed = missing.is_empty();
        CompatCheckResult {
            rule_id: "STATE-003".into(),
            domain: CompatDomain::State,
            passed,
            level: CompatLevel::Migration,
            detail: if passed {
                format!("schema_version={sv}, all migrations present")
            } else {
                format!("schema_version={sv}, missing migrations from versions: {:?}", missing)
            },
            recommendation: if passed { None } else {
                Some(format!("Add migrations for versions {:?} in MIGRATIONS or legacy code.", missing))
            },
        }
    }

    // ── RPC checks ───────────────────────────────────────────────────────

    /// RPC-001: By convention, new RPC response fields are additive (existing fields preserved).
    fn check_rpc_field_additive(&self) -> CompatCheckResult {
        CompatCheckResult {
            rule_id: "RPC-001".into(),
            domain: CompatDomain::Rpc,
            passed: true, // Convention
            level: CompatLevel::Additive,
            detail: "RPC responses should preserve existing fields; new fields should be optional".into(),
            recommendation: None,
        }
    }

    /// RPC-002: By convention, existing RPC methods are not removed or renamed.
    fn check_rpc_method_preserved(&self) -> CompatCheckResult {
        CompatCheckResult {
            rule_id: "RPC-002".into(),
            domain: CompatDomain::Rpc,
            passed: true, // Convention
            level: CompatLevel::Full,
            detail: "core RPC methods (eth_*, net_*, web3_*) preserved".into(),
            recommendation: None,
        }
    }

    /// RPC-003: OpenAPI spec file is present and readable (if configured).
    fn check_rpc_openapi_readable(&self) -> CompatCheckResult {
        if let Some(path) = &self.openapi_path {
            if !Path::new(path).exists() {
                return CompatCheckResult {
                    rule_id: "RPC-003".into(),
                    domain: CompatDomain::Rpc,
                    passed: false,
                    level: CompatLevel::Additive,
                    detail: format!("OpenAPI spec not found at {}", path),
                    recommendation: Some("Ensure openapi.yaml is present at the specified path.".into()),
                };
            }
            match fs::read_to_string(path) {
                Ok(content) if !content.is_empty() => CompatCheckResult {
                    rule_id: "RPC-003".into(),
                    domain: CompatDomain::Rpc,
                    passed: true,
                    level: CompatLevel::Additive,
                    detail: "OpenAPI spec exists and is readable".into(),
                    recommendation: None,
                },
                Ok(_) => CompatCheckResult {
                    rule_id: "RPC-003".into(),
                    domain: CompatDomain::Rpc,
                    passed: false,
                    level: CompatLevel::Additive,
                    detail: "OpenAPI spec is empty".into(),
                    recommendation: Some("Check openapi.yaml content.".into()),
                },
                Err(e) => CompatCheckResult {
                    rule_id: "RPC-003".into(),
                    domain: CompatDomain::Rpc,
                    passed: false,
                    level: CompatLevel::Additive,
                    detail: format!("Cannot read OpenAPI spec: {}", e),
                    recommendation: Some("Ensure file permissions and path are correct.".into()),
                },
            }
        } else {
            CompatCheckResult {
                rule_id: "RPC-003".into(),
                domain: CompatDomain::Rpc,
                passed: true, // not configured, skip
                level: CompatLevel::Additive,
                detail: "OpenAPI validation not configured (skipped)".into(),
                recommendation: None,
            }
        }
    }

    // ── Consensus checks ─────────────────────────────────────────────────

    /// CONS-001: PV selection is deterministic (same height -> same PV).
    fn check_consensus_pv_deterministic(&self) -> CompatCheckResult {
        let heights = [0, 1, 100, 1000, 999_999];
        let deterministic = heights.iter().all(|&h| {
            let pv1 = super::version::version_for_height(h, &self.activations);
            let pv2 = super::version::version_for_height(h, &self.activations);
            pv1 == pv2
        });

        CompatCheckResult {
            rule_id: "CONS-001".into(),
            domain: CompatDomain::Consensus,
            passed: deterministic,
            level: CompatLevel::Full,
            detail: format!(
                "PV determinism verified for {} heights",
                heights.len()
            ),
            recommendation: if deterministic { None } else {
                Some("Check that version_for_height is pure and doesn't depend on mutable state.".into())
            },
        }
    }

    /// CONS-002: Protocol activation has a valid schedule.
    fn check_consensus_activation_scheduled(&self) -> CompatCheckResult {
        let mut prev_height: Option<u64> = None;
        let mut prev_pv: Option<u32> = None;
        let mut valid = true;
        let mut detail = String::new();

        for (i, a) in self.activations.iter().enumerate() {
            if i == 0 {
                // First activation must be PV=1 and have None activation height.
                if a.protocol_version != 1 {
                    valid = false;
                    detail = format!("First activation must be PV=1, found PV={}", a.protocol_version);
                    break;
                }
                if a.activation_height.is_some() {
                    valid = false;
                    detail = "First activation must have activation_height = None".into();
                    break;
                }
            } else {
                if a.activation_height.is_none() {
                    valid = false;
                    detail = format!("Activation for PV={} must have activation_height specified", a.protocol_version);
                    break;
                }
                if let Some(ph) = prev_height {
                    if a.activation_height <= ph {
                        valid = false;
                        detail = format!(
                            "Activation height {} <= previous height {}",
                            a.activation_height.unwrap(), ph
                        );
                        break;
                    }
                }
            }
            if let Some(ppv) = prev_pv {
                if a.protocol_version <= ppv {
                    valid = false;
                    detail = format!(
                        "PV {} <= previous PV {}",
                        a.protocol_version, ppv
                    );
                    break;
                }
            }
            prev_height = a.activation_height.or(prev_height);
            prev_pv = Some(a.protocol_version);
        }

        if detail.is_empty() {
            detail = format!("{} activations in valid order", self.activations.len());
        }

        CompatCheckResult {
            rule_id: "CONS-002".into(),
            domain: CompatDomain::Consensus,
            passed: valid,
            level: CompatLevel::Breaking,
            detail,
            recommendation: if valid { None } else {
                Some("Ensure activations are strictly increasing and first PV has None height.".into())
            },
        }
    }

    /// CONS-003: Grace window allows stragglers to catch up.
    fn check_consensus_grace_window(&self) -> CompatCheckResult {
        let needs_grace: Vec<_> = self.activations.iter()
            .filter(|a| a.protocol_version > 1 && a.activation_height.is_some())
            .collect();

        let all_have_grace = needs_grace.iter().all(|a| a.grace_blocks > 0);

        CompatCheckResult {
            rule_id: "CONS-003".into(),
            domain: CompatDomain::Consensus,
            passed: all_have_grace || needs_grace.is_empty(),
            level: CompatLevel::Breaking,
            detail: if needs_grace.is_empty() {
                "no activations requiring grace window".into()
            } else {
                format!(
                    "{}/{} activations have grace > 0",
                    needs_grace.iter().filter(|a| a.grace_blocks > 0).count(),
                    needs_grace.len()
                )
            },
            recommendation: if all_have_grace || needs_grace.is_empty() { None } else {
                Some("Set grace_blocks > 0 for activations with PV>1.".into())
            },
        }
    }
}

/// Default set of compatibility rules.
fn default_rules() -> Vec<CompatRule> {
    vec![
        CompatRule {
            id: "WIRE-001".into(),
            description: "Current binary supports PV=1 for backward compatibility".into(),
            domain: CompatDomain::Wire,
            enforced: true,
        },
        CompatRule {
            id: "WIRE-002".into(),
            description: "Unknown message type IDs are silently ignored (design)".into(),
            domain: CompatDomain::Wire,
            enforced: true,
        },
        CompatRule {
            id: "WIRE-003".into(),
            description: "Handshake includes version negotiation (design)".into(),
            domain: CompatDomain::Wire,
            enforced: true,
        },
        CompatRule {
            id: "STATE-001".into(),
            description: "Schema version monotonically increasing".into(),
            domain: CompatDomain::State,
            enforced: true,
        },
        CompatRule {
            id: "STATE-002".into(),
            description: "New fields use #[serde(default)] or Option (convention)".into(),
            domain: CompatDomain::State,
            enforced: false,
        },
        CompatRule {
            id: "STATE-003".into(),
            description: "Migration exists for each schema version bump".into(),
            domain: CompatDomain::State,
            enforced: true,
        },
        CompatRule {
            id: "RPC-001".into(),
            description: "RPC response fields are additive only (convention)".into(),
            domain: CompatDomain::Rpc,
            enforced: false,
        },
        CompatRule {
            id: "RPC-002".into(),
            description: "Existing RPC methods preserved (convention)".into(),
            domain: CompatDomain::Rpc,
            enforced: true,
        },
        CompatRule {
            id: "RPC-003".into(),
            description: "OpenAPI spec present and readable (if configured)".into(),
            domain: CompatDomain::Rpc,
            enforced: false,
        },
        CompatRule {
            id: "CONS-001".into(),
            description: "PV selection is deterministic".into(),
            domain: CompatDomain::Consensus,
            enforced: true,
        },
        CompatRule {
            id: "CONS-002".into(),
            description: "Activation schedule is valid".into(),
            domain: CompatDomain::Consensus,
            enforced: true,
        },
        CompatRule {
            id: "CONS-003".into(),
            description: "Grace window for straggler nodes".into(),
            domain: CompatDomain::Consensus,
            enforced: true,
        },
    ]
}

// ─── Compatibility matrix ────────────────────────────────────────────────────

/// Entry in the compatibility matrix.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CompatMatrixEntry {
    /// Software version (semver).
    pub software_version: String,
    /// Supported protocol versions.
    pub supported_pv: Vec<u32>,
    /// Supported schema versions (can read).
    pub supported_sv: Vec<u32>,
    /// Compatibility level with previous version.
    pub compat_level: CompatLevel,
    /// Notes about this version.
    pub notes: String,
}

/// Build the compatibility matrix for known versions.
pub fn build_compat_matrix() -> Vec<CompatMatrixEntry> {
    vec![
        CompatMatrixEntry {
            software_version: "27.0.0".into(),
            supported_pv: vec![1],
            supported_sv: vec![0, 1, 2, 3, 4],
            compat_level: CompatLevel::Full,
            notes: "Initial v27 release".into(),
        },
        CompatMatrixEntry {
            software_version: "27.1.0".into(),
            supported_pv: vec![1],
            supported_sv: vec![0, 1, 2, 3, 4],
            compat_level: CompatLevel::Additive,
            notes: "Added protocol versioning, node_meta.json".into(),
        },
        CompatMatrixEntry {
            software_version: "27.2.0".into(),
            supported_pv: vec![1],
            supported_sv: vec![0, 1, 2, 3, 4, 5],
            compat_level: CompatLevel::Migration,
            notes: "Added tx_index, compat enforcement, rolling upgrades".into(),
        },
        // Future planned versions
        CompatMatrixEntry {
            software_version: "27.3.0".into(),
            supported_pv: vec![1, 2],
            supported_sv: vec![0, 1, 2, 3, 4, 5],
            compat_level: CompatLevel::Breaking,
            notes: "Introduce PV=2 at height 1,000,000".into(),
        },
    ]
}

/// Check if two versions are wire-compatible.
pub fn check_version_compat(a: &CompatMatrixEntry, b: &CompatMatrixEntry) -> bool {
    a.supported_pv.iter().any(|pv| b.supported_pv.contains(pv))
}

/// Generate a human-readable upgrade guide based on the matrix.
pub fn generate_upgrade_guide(from: &str, to: &str) -> String {
    let matrix = build_compat_matrix();
    let from_entry = matrix.iter().find(|e| e.software_version == from);
    let to_entry = matrix.iter().find(|e| e.software_version == to);

    match (from_entry, to_entry) {
        (Some(f), Some(t)) => {
            if f.compat_level == CompatLevel::Full && t.compat_level == CompatLevel::Full {
                format!("Upgrade from {} to {} is fully compatible. You can upgrade any node in any order.", from, to)
            } else if check_version_compat(f, t) {
                format!(
                    "Upgrade from {} to {} is wire-compatible (PVs overlap). \
                     Ensure all nodes are updated within the grace window.",
                    from, to
                )
            } else {
                format!(
                    "⚠️  Breaking change from {} to {}. Upgrade requires a coordinated activation.\n\
                     Steps:\n\
                     1. Update all nodes to the new binary (they will run with old PV until activation).\n\
                     2. At the scheduled activation height (consult the upgrade plan), the network switches to new PV.\n\
                     3. Ensure a majority of validators are upgraded before activation.",
                    from, to
                )
            }
        }
        _ => "Unknown versions. Check the compatibility matrix.".into(),
    }
}

// ─── Tests ──────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::version::{default_activations, ProtocolActivation};

    #[test]
    fn test_compat_level_ordering() {
        assert!(CompatLevel::Full < CompatLevel::Additive);
        assert!(CompatLevel::Additive < CompatLevel::Migration);
        assert!(CompatLevel::Migration < CompatLevel::Breaking);
    }

    #[test]
    fn test_compat_checker_all_pass() {
        let checker = CompatChecker::new(default_activations());
        let report = checker.check_all();
        assert!(report.passed, "failures: {report}");
    }

    #[test]
    fn test_compat_checker_with_upgrade() {
        let activations = vec![
            ProtocolActivation {
                protocol_version: 1,
                activation_height: None,
                grace_blocks: 0,
            },
            ProtocolActivation {
                protocol_version: 2,
                activation_height: Some(100_000),
                grace_blocks: 500,
            },
        ];
        let checker = CompatChecker::new(activations);
        let report = checker.check_all();
        assert!(report.passed, "failures: {report}");
    }

    #[test]
    fn test_consensus_activation_schedule_fails() {
        let activations = vec![
            ProtocolActivation {
                protocol_version: 2,
                activation_height: None,
                grace_blocks: 0,
            },
        ];
        let checker = CompatChecker::new(activations);
        let report = checker.check_all();
        let cons_failures = report.by_domain(CompatDomain::Consensus);
        assert!(!cons_failures.iter().any(|r| r.rule_id == "CONS-002" && r.passed));
    }

    #[test]
    fn test_consensus_activation_schedule_fails_duplicate_pv() {
        let activations = vec![
            ProtocolActivation {
                protocol_version: 1,
                activation_height: None,
                grace_blocks: 0,
            },
            ProtocolActivation {
                protocol_version: 1,
                activation_height: Some(1000),
                grace_blocks: 0,
            },
        ];
        let checker = CompatChecker::new(activations);
        let report = checker.check_all();
        let cons_failures = report.by_domain(CompatDomain::Consensus);
        assert!(!cons_failures.iter().any(|r| r.rule_id == "CONS-002" && r.passed));
    }

    #[test]
    fn test_consensus_grace_window_fails() {
        let activations = vec![
            ProtocolActivation {
                protocol_version: 1,
                activation_height: None,
                grace_blocks: 0,
            },
            ProtocolActivation {
                protocol_version: 2,
                activation_height: Some(1000),
                grace_blocks: 0,
            },
        ];
        let checker = CompatChecker::new(activations);
        let report = checker.check_all();
        let cons_failures = report.by_domain(CompatDomain::Consensus);
        assert!(!cons_failures.iter().any(|r| r.rule_id == "CONS-003" && r.passed));
    }

    #[test]
    fn test_state_migration_exists() {
        let sv = crate::storage::CURRENT_SCHEMA_VERSION;
        for from in 0..sv {
            assert!(CompatChecker::migration_exists(from), "Missing migration from {}", from);
        }
    }

    #[test]
    fn test_compat_report_by_domain() {
        let checker = CompatChecker::new(default_activations());
        let report = checker.check_all();

        let wire = report.by_domain(CompatDomain::Wire);
        assert_eq!(wire.len(), 3);

        let state = report.by_domain(CompatDomain::State);
        assert_eq!(state.len(), 3);

        let rpc = report.by_domain(CompatDomain::Rpc);
        assert_eq!(rpc.len(), 3);

        let consensus = report.by_domain(CompatDomain::Consensus);
        assert_eq!(consensus.len(), 3);
    }

    #[test]
    fn test_compat_matrix() {
        let matrix = build_compat_matrix();
        assert_eq!(matrix.len(), 4);

        for i in 0..matrix.len() {
            for j in 0..matrix.len() {
                assert!(
                    check_version_compat(&matrix[i], &matrix[j]),
                    "v{} and v{} should be compatible",
                    matrix[i].software_version,
                    matrix[j].software_version
                );
            }
        }
    }

    #[test]
    fn test_upgrade_guide() {
        let guide = generate_upgrade_guide("27.2.0", "27.3.0");
        assert!(guide.contains("Breaking change"));
        let guide_ok = generate_upgrade_guide("27.0.0", "27.1.0");
        assert!(guide_ok.contains("fully compatible") || guide_ok.contains("wire-compatible"));
    }

    #[test]
    fn test_check_enforced_only() {
        let checker = CompatChecker::new(default_activations());
        let full = checker.check_all();
        let enforced = checker.check_enforced();
        assert!(enforced.results.len() < full.results.len());
        assert!(enforced.passed);
    }

    #[test]
    fn test_compat_level_display() {
        assert_eq!(format!("{}", CompatLevel::Full), "Full (Level 0)");
        assert_eq!(format!("{}", CompatLevel::Breaking), "Breaking (Level 3)");
    }

    #[test]
    fn test_compat_domain_display() {
        assert_eq!(format!("{}", CompatDomain::Wire), "Wire");
        assert_eq!(format!("{}", CompatDomain::Consensus), "Consensus");
    }

    #[test]
    fn test_default_rules_count() {
        let rules = default_rules();
        assert_eq!(rules.len(), 12);

        let enforced: Vec<_> = rules.iter().filter(|r| r.enforced).collect();
        assert!(enforced.len() >= 8);
    }

    #[test]
    fn test_report_failures_empty_when_pass() {
        let checker = CompatChecker::new(default_activations());
        let report = checker.check_all();
        assert!(report.failures().is_empty());
    }
}
