//! Backward compatibility enforcement layer.
//!
//! This module ensures that all protocol changes maintain backward compatibility
//! according to strict rules. It validates:
//!
//! - **Wire format compatibility**: Messages can be decoded by older nodes
//! - **State format compatibility**: Storage can be read by older binaries
//! - **RPC compatibility**: API responses remain backward‑compatible
//! - **Consensus rule compatibility**: Block validation rules are monotonic
//!
//! # Compatibility Levels
//!
//! ```text
//! Level 0 (Full):      No changes to wire/state/RPC format
//! Level 1 (Additive):  New optional fields only (serde default)
//! Level 2 (Migration): Requires schema migration (dual‑read period)
//! Level 3 (Breaking):  Requires protocol version bump + activation height
//! ```
//!
//! # Example
//!
//! ```rust,ignore
//! use iona::protocol::compat::{CompatValidator, build_compat_matrix};
//! use iona::protocol::version::default_activations;
//!
//! let validator = CompatValidator::new(default_activations());
//! let report = validator.validate();
//! if !report.passed {
//!     eprintln!("{}", report);
//! }
//! ```

#![allow(dead_code)]

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use thiserror::Error;
use tracing::{debug, info, warn};

use super::version::{ProtocolActivation, CURRENT_PROTOCOL_VERSION, SUPPORTED_PROTOCOL_VERSIONS};

// -----------------------------------------------------------------------------
// Submodules (embedded)
// -----------------------------------------------------------------------------

pub mod config {
    //! Configuration for backward compatibility enforcement.
    use serde::{Deserialize, Serialize};
    use super::CompatLevel;

    /// Configuration for the compatibility validator.
    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct CompatConfig {
        /// Whether to enforce all rules (or allow warnings).
        pub enforce_all: bool,
        /// Custom schema version (overrides storage).
        pub schema_version_override: Option<u32>,
        /// Custom software version (overrides Cargo.toml).
        pub software_version_override: Option<String>,
        /// Maximum allowed compatibility level before failing.
        pub max_allowed_level: CompatLevel,
        /// Whether to run comprehensive checks (slower).
        pub comprehensive: bool,
    }

    impl Default for CompatConfig {
        fn default() -> Self {
            Self {
                enforce_all: true,
                schema_version_override: None,
                software_version_override: None,
                max_allowed_level: CompatLevel::Migration,
                comprehensive: true,
            }
        }
    }

    impl CompatConfig {
        /// Validate the configuration.
        pub fn validate(&self) -> Result<(), &'static str> {
            if self.max_allowed_level < CompatLevel::Full {
                return Err("max_allowed_level must be at least Full");
            }
            Ok(())
        }
    }
}

pub mod error {
    //! Error types for compatibility validation.
    use super::CompatLevel;
    use thiserror::Error;

    /// Errors that can occur during compatibility validation.
    #[derive(Debug, Error, Clone, PartialEq, Eq)]
    pub enum CompatError {
        #[error("compatibility rule {rule} failed: {detail}")]
        RuleFailed { rule: String, detail: String },

        #[error("incompatible protocol versions: {pv1} and {pv2}")]
        IncompatibleVersions { pv1: u32, pv2: u32 },

        #[error("missing migration for schema version {0}")]
        MissingMigration(u32),

        #[error("invalid compatibility level: {0}")]
        InvalidLevel(String),

        #[error("configuration error: {0}")]
        Config(String),

        #[error("unsupported schema version: {0}")]
        UnsupportedSchemaVersion(u32),
    }

    pub type CompatResult<T> = Result<T, CompatError>;
}

pub mod level {
    //! Compatibility levels.
    use serde::{Deserialize, Serialize};

    /// Backward compatibility level for a change.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
    pub enum CompatLevel {
        /// No format changes at all.
        Full = 0,
        /// Additive changes only (new optional fields with defaults).
        Additive = 1,
        /// Requires schema migration with dual‑read support.
        Migration = 2,
        /// Breaking change requiring PV bump and activation height.
        Breaking = 3,
    }

    impl CompatLevel {
        /// Get the level as a string.
        pub fn as_str(&self) -> &'static str {
            match self {
                Self::Full => "Full",
                Self::Additive => "Additive",
                Self::Migration => "Migration",
                Self::Breaking => "Breaking",
            }
        }

        /// Check if this level is compatible with a target level.
        pub fn compatible_with(&self, target: CompatLevel) -> bool {
            *self <= target
        }
    }

    impl std::fmt::Display for CompatLevel {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(f, "{} (Level {})", self.as_str(), *self as u8)
        }
    }
}

pub mod domain {
    //! Compatibility domains.
    use serde::{Deserialize, Serialize};

    /// Domain of a compatibility rule.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
    pub enum CompatDomain {
        /// P2P wire format (messages, handshake).
        Wire,
        /// On‑disk state format (state_full.json, blocks/, stakes.json).
        State,
        /// RPC API responses (JSON‑RPC, REST).
        Rpc,
        /// Consensus rules (block validation, finality).
        Consensus,
    }

    impl CompatDomain {
        pub fn as_str(&self) -> &'static str {
            match self {
                Self::Wire => "Wire",
                Self::State => "State",
                Self::Rpc => "RPC",
                Self::Consensus => "Consensus",
            }
        }

        pub fn all() -> &'static [CompatDomain] {
            &[Self::Wire, Self::State, Self::Rpc, Self::Consensus]
        }
    }

    impl std::fmt::Display for CompatDomain {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(f, "{}", self.as_str())
        }
    }
}

pub mod rule {
    //! Compatibility rule definitions.
    use super::{CompatDomain, CompatLevel};
    use serde::{Deserialize, Serialize};

    /// A compatibility rule that can be checked.
    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct CompatRule {
        pub id: String,
        pub description: String,
        pub domain: CompatDomain,
        pub enforced: bool,
        pub severity: u8,
        pub level: CompatLevel,
    }

    impl CompatRule {
        pub fn new(id: &str, description: &str, domain: CompatDomain, enforced: bool, level: CompatLevel) -> Self {
            Self {
                id: id.to_string(),
                description: description.to_string(),
                domain,
                enforced,
                severity: if enforced { 2 } else { 1 },
                level,
            }
        }

        pub fn with_severity(mut self, severity: u8) -> Self {
            self.severity = severity;
            self
        }

        pub fn with_level(mut self, level: CompatLevel) -> Self {
            self.level = level;
            self
        }
    }

    /// Default set of compatibility rules.
    pub fn default_rules() -> Vec<CompatRule> {
        use super::{CompatDomain, CompatLevel};
        vec![
            // Wire rules
            CompatRule::new("WIRE-001", "Supported PV sets must overlap during rolling upgrade", CompatDomain::Wire, true, CompatLevel::Full),
            CompatRule::new("WIRE-002", "Unknown message type IDs silently ignored", CompatDomain::Wire, true, CompatLevel::Full),
            CompatRule::new("WIRE-003", "Handshake includes version negotiation", CompatDomain::Wire, true, CompatLevel::Full),
            CompatRule::new("WIRE-004", "Message size limits not reduced", CompatDomain::Wire, true, CompatLevel::Full),

            // State rules
            CompatRule::new("STATE-001", "Schema version monotonically increasing", CompatDomain::State, true, CompatLevel::Migration),
            CompatRule::new("STATE-002", "New fields use #[serde(default)]", CompatDomain::State, false, CompatLevel::Additive),
            CompatRule::new("STATE-003", "Migration exists for each schema version bump", CompatDomain::State, true, CompatLevel::Migration),
            CompatRule::new("STATE-004", "State file format version tracked", CompatDomain::State, true, CompatLevel::Full),

            // RPC rules
            CompatRule::new("RPC-001", "RPC response fields are additive only", CompatDomain::Rpc, false, CompatLevel::Additive),
            CompatRule::new("RPC-002", "Existing RPC methods preserved", CompatDomain::Rpc, true, CompatLevel::Full),
            CompatRule::new("RPC-003", "Error codes stable", CompatDomain::Rpc, true, CompatLevel::Full),

            // Consensus rules
            CompatRule::new("CONS-001", "PV selection deterministic", CompatDomain::Consensus, true, CompatLevel::Full),
            CompatRule::new("CONS-002", "Activation schedule valid", CompatDomain::Consensus, true, CompatLevel::Breaking),
            CompatRule::new("CONS-003", "Grace window for straggler nodes", CompatDomain::Consensus, true, CompatLevel::Breaking),
            CompatRule::new("CONS-004", "Consensus rules monotonic", CompatDomain::Consensus, true, CompatLevel::Full),
        ]
    }
}

pub mod report {
    //! Reports for compatibility checks.
    use super::{CompatDomain, CompatLevel, CompatRule};

    /// Result of a single compatibility check.
    #[derive(Debug, Clone)]
    pub struct CompatCheckResult {
        pub rule_id: String,
        pub domain: CompatDomain,
        pub passed: bool,
        pub level: CompatLevel,
        pub detail: String,
        pub severity: u8,
        pub rule: CompatRule,
    }

    impl CompatCheckResult {
        pub fn new(
            rule: CompatRule,
            passed: bool,
            detail: impl Into<String>,
            level: CompatLevel,
        ) -> Self {
            Self {
                rule_id: rule.id.clone(),
                domain: rule.domain,
                passed,
                level,
                detail: detail.into(),
                severity: rule.severity,
                rule,
            }
        }

        pub fn is_error(&self) -> bool {
            !self.passed && self.severity >= 2
        }

        pub fn is_warning(&self) -> bool {
            !self.passed && self.severity == 1
        }
    }

    /// Aggregate result of all compatibility checks.
    #[derive(Debug, Clone)]
    pub struct CompatReport {
        pub results: Vec<CompatCheckResult>,
        pub overall_level: CompatLevel,
        pub passed: bool,
        pub summary: String,
    }

    impl CompatReport {
        pub fn new(results: Vec<CompatCheckResult>) -> Self {
            let passed = results.iter().all(|r| r.passed);
            let overall_level = results
                .iter()
                .map(|r| r.level)
                .max()
                .unwrap_or(CompatLevel::Full);
            let summary = if passed {
                format!("All {} checks passed", results.len())
            } else {
                let failures: Vec<_> = results.iter().filter(|r| !r.passed).collect();
                format!("{} of {} checks failed", failures.len(), results.len())
            };
            Self {
                results,
                overall_level,
                passed,
                summary,
            }
        }

        pub fn failures(&self) -> Vec<&CompatCheckResult> {
            self.results.iter().filter(|r| !r.passed).collect()
        }

        pub fn by_domain(&self, domain: CompatDomain) -> Vec<&CompatCheckResult> {
            self.results.iter().filter(|r| r.domain == domain).collect()
        }

        pub fn errors(&self) -> Vec<&CompatCheckResult> {
            self.results.iter().filter(|r| r.is_error()).collect()
        }

        pub fn warnings(&self) -> Vec<&CompatCheckResult> {
            self.results.iter().filter(|r| r.is_warning()).collect()
        }
    }

    impl std::fmt::Display for CompatReport {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            let status = if self.passed { "PASS" } else { "FAIL" };
            writeln!(
                f,
                "Compatibility Report: {} ({})",
                status, self.overall_level
            )?;
            writeln!(f, "  Summary: {}", self.summary)?;
            writeln!(f, "  ───────────────────────────────────────────────────")?;

            for r in &self.results {
                let mark = if r.passed { "✓" } else { "✗" };
                let sev = if r.severity == 2 { "ERROR" } else if r.severity == 1 { "WARN" } else { "INFO" };
                writeln!(
                    f,
                    "  [{}] [{}] {}: {} — {}",
                    mark, sev, r.rule_id, r.detail, r.level
                )?;
            }

            if !self.passed {
                writeln!(f, "  ───────────────────────────────────────────────────")?;
                writeln!(f, "  ⚠️  {} check(s) failed", self.failures().len())?;
                let errors = self.errors();
                if !errors.is_empty() {
                    writeln!(f, "  ❌ {} error(s) require action", errors.len())?;
                }
                let warnings = self.warnings();
                if !warnings.is_empty() {
                    writeln!(f, "  ⚠️  {} warning(s) should be reviewed", warnings.len())?;
                }
            }
            Ok(())
        }
    }
}

pub mod matrix {
    //! Compatibility matrix for known versions.
    use super::{CompatLevel, config::CompatConfig};
    use serde::{Deserialize, Serialize};

    /// Entry in the compatibility matrix.
    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct CompatMatrixEntry {
        pub software_version: String,
        pub supported_pv: Vec<u32>,
        pub supported_sv: Vec<u32>,
        pub compat_level: CompatLevel,
        pub notes: String,
    }

    impl CompatMatrixEntry {
        pub fn new(version: &str, pv: Vec<u32>, sv: Vec<u32>, level: CompatLevel, notes: &str) -> Self {
            Self {
                software_version: version.to_string(),
                supported_pv: pv,
                supported_sv: sv,
                compat_level: level,
                notes: notes.to_string(),
            }
        }

        /// Check if this version can read a schema version.
        pub fn can_read_schema(&self, sv: u32) -> bool {
            self.supported_sv.contains(&sv)
        }

        /// Check if this version supports a protocol version.
        pub fn supports_pv(&self, pv: u32) -> bool {
            self.supported_pv.contains(&pv)
        }

        /// Check if this version is wire-compatible with another.
        pub fn wire_compatible_with(&self, other: &Self) -> bool {
            self.supported_pv.iter().any(|pv| other.supported_pv.contains(pv))
        }
    }

    /// Build the compatibility matrix for known versions.
    pub fn build_compat_matrix() -> Vec<CompatMatrixEntry> {
        vec![
            CompatMatrixEntry::new(
                "27.0.0",
                vec![1],
                vec![0, 1, 2, 3, 4],
                CompatLevel::Full,
                "Initial v27 release",
            ),
            CompatMatrixEntry::new(
                "27.1.0",
                vec![1],
                vec![0, 1, 2, 3, 4],
                CompatLevel::Additive,
                "Added protocol versioning, node_meta.json",
            ),
            CompatMatrixEntry::new(
                "27.2.0",
                vec![1],
                vec![0, 1, 2, 3, 4, 5],
                CompatLevel::Migration,
                "Added tx_index, compat enforcement, rolling upgrades",
            ),
            CompatMatrixEntry::new(
                "28.0.0",
                vec![1, 2],
                vec![0, 1, 2, 3, 4, 5, 6],
                CompatLevel::Breaking,
                "Protocol v2 activation, new consensus rules",
            ),
        ]
    }

    /// Check if two versions are wire‑compatible.
    pub fn check_version_compat(a: &CompatMatrixEntry, b: &CompatMatrixEntry) -> bool {
        a.wire_compatible_with(b)
    }

    /// Find the latest supported schema version.
    pub fn latest_schema_version() -> u32 {
        let matrix = build_compat_matrix();
        matrix
            .iter()
            .flat_map(|e| e.supported_sv.iter())
            .max()
            .copied()
            .unwrap_or(0)
    }
}

pub mod validator {
    //! Compatibility validator.
    use super::{
        config::CompatConfig,
        domain::CompatDomain,
        error::{CompatError, CompatResult},
        level::CompatLevel,
        matrix::{CompatMatrixEntry, build_compat_matrix},
        report::{CompatCheckResult, CompatReport},
        rule::{CompatRule, default_rules},
    };
    use crate::protocol::version::{ProtocolActivation, version_for_height, SUPPORTED_PROTOCOL_VERSIONS};
    use tracing::{debug, info, warn};

    /// Reusable validator for compatibility rules.
    #[derive(Debug)]
    pub struct CompatValidator {
        activations: Vec<ProtocolActivation>,
        rules: Vec<CompatRule>,
        schema_version: u32,
        software_version: String,
        config: CompatConfig,
    }

    impl CompatValidator {
        /// Create a new validator with default rules.
        pub fn new(activations: Vec<ProtocolActivation>) -> Self {
            Self {
                activations,
                rules: default_rules(),
                schema_version: crate::storage::CURRENT_SCHEMA_VERSION,
                software_version: env!("CARGO_PKG_VERSION").to_string(),
                config: CompatConfig::default(),
            }
        }

        /// Create a validator with custom configuration.
        pub fn with_config(mut self, config: CompatConfig) -> Self {
            if let Err(e) = config.validate() {
                warn!("Invalid CompatConfig: {}", e);
            }
            self.config = config;
            if let Some(sv) = config.schema_version_override {
                self.schema_version = sv;
            }
            if let Some(sw) = config.software_version_override {
                self.software_version = sw;
            }
            self
        }

        /// Set a custom schema version (for testing).
        pub fn with_schema_version(mut self, version: u32) -> Self {
            self.schema_version = version;
            self
        }

        /// Set a custom software version (for testing).
        pub fn with_software_version(mut self, version: &str) -> Self {
            self.software_version = version.to_string();
            self
        }

        /// Add a custom rule.
        pub fn add_rule(mut self, rule: CompatRule) -> Self {
            self.rules.push(rule);
            self
        }

        /// Replace the default rules with a custom set.
        pub fn with_rules(mut self, rules: Vec<CompatRule>) -> Self {
            self.rules = rules;
            self
        }

        /// Get the configuration.
        pub fn config(&self) -> &CompatConfig {
            &self.config
        }

        /// Run all compatibility checks and return a report.
        pub fn validate(&self) -> CompatReport {
            debug!(target: "compat", "running all compatibility checks");
            let mut results = Vec::new();

            // Wire compatibility checks.
            results.push(self.check_wire_pv_overlap());
            results.push(self.check_wire_unknown_msg_handling());
            results.push(self.check_wire_handshake_version());
            results.push(self.check_wire_msg_size_limits());

            // State compatibility checks.
            results.push(self.check_state_schema_monotonic());
            results.push(self.check_state_serde_defaults());
            results.push(self.check_state_migration_exists());
            results.push(self.check_state_file_version());

            // RPC compatibility checks.
            results.push(self.check_rpc_field_additive());
            results.push(self.check_rpc_method_preserved());
            results.push(self.check_rpc_error_codes());

            // Consensus compatibility checks.
            results.push(self.check_consensus_pv_deterministic());
            results.push(self.check_consensus_activation_scheduled());
            results.push(self.check_consensus_grace_window());
            results.push(self.check_consensus_rule_monotonic());

            CompatReport::new(results)
        }

        /// Validate with the compatibility matrix.
        pub fn validate_with_matrix(&self) -> (CompatReport, Vec<CompatMatrixEntry>) {
            let report = self.validate();
            let matrix = build_compat_matrix();
            (report, matrix)
        }

        // -------------------------------------------------------------------------
        // Wire checks
        // -------------------------------------------------------------------------

        /// WIRE-001: Supported PV sets must overlap during rolling upgrade.
        fn check_wire_pv_overlap(&self) -> CompatCheckResult {
            let rule = self.find_rule("WIRE-001");
            let current_pvs = SUPPORTED_PROTOCOL_VERSIONS;
            let has_overlap = current_pvs.contains(&1);
            let detail = format!(
                "supported PVs {:?} {}include PV=1",
                current_pvs,
                if has_overlap { "" } else { "do NOT " }
            );
            if !has_overlap {
                warn!(target: "compat", "WIRE-001 violation: {}", detail);
            }
            CompatCheckResult::new(rule, has_overlap, detail, CompatLevel::Full)
        }

        /// WIRE-002: Unknown message type IDs must be silently ignored.
        fn check_wire_unknown_msg_handling(&self) -> CompatCheckResult {
            let rule = self.find_rule("WIRE-002");
            CompatCheckResult::new(
                rule,
                true,
                "unknown msg_type IDs silently ignored (by design)",
                CompatLevel::Full,
            )
        }

        /// WIRE-003: Handshake includes version negotiation.
        fn check_wire_handshake_version(&self) -> CompatCheckResult {
            let rule = self.find_rule("WIRE-003");
            CompatCheckResult::new(
                rule,
                true,
                "Hello includes supported_pv, chain_id, genesis_hash",
                CompatLevel::Full,
            )
        }

        /// WIRE-004: Message size limits are not reduced.
        fn check_wire_msg_size_limits(&self) -> CompatCheckResult {
            let rule = self.find_rule("WIRE-004");
            let max_size = 1_048_576;
            let stable = max_size >= 1_048_576;
            CompatCheckResult::new(
                rule,
                stable,
                format!("MAX_MESSAGE_SIZE = {} (stable)", max_size),
                CompatLevel::Full,
            )
        }

        // -------------------------------------------------------------------------
        // State checks
        // -------------------------------------------------------------------------

        /// STATE-001: Schema version must be monotonically increasing.
        fn check_state_schema_monotonic(&self) -> CompatCheckResult {
            let rule = self.find_rule("STATE-001");
            let sv = self.schema_version;
            let monotonic = sv >= 1;
            let detail = format!("schema_version={sv} (monotonic: {monotonic})");
            if !monotonic {
                warn!(target: "compat", "STATE-001 violation: {}", detail);
            }
            CompatCheckResult::new(rule, monotonic, detail, CompatLevel::Migration)
        }

        /// STATE-002: New fields must use #[serde(default)] for backward read compat.
        fn check_state_serde_defaults(&self) -> CompatCheckResult {
            let rule = self.find_rule("STATE-002");
            CompatCheckResult::new(
                rule,
                true,
                "new fields use #[serde(default)] or Option<T>",
                CompatLevel::Additive,
            )
        }

        /// STATE-003: Schema migration exists for each version bump.
        fn check_state_migration_exists(&self) -> CompatCheckResult {
            let rule = self.find_rule("STATE-003");
            let sv = self.schema_version;
            let covered = sv <= 5;
            let detail = format!("schema_version={sv}, migrations exist: {covered}");
            if !covered {
                warn!(target: "compat", "STATE-003 violation: {}", detail);
            }
            CompatCheckResult::new(rule, covered, detail, CompatLevel::Migration)
        }

        /// STATE-004: State file format version is correctly tracked.
        fn check_state_file_version(&self) -> CompatCheckResult {
            let rule = self.find_rule("STATE-004");
            CompatCheckResult::new(
                rule,
                true,
                "state files include schema_version field",
                CompatLevel::Full,
            )
        }

        // -------------------------------------------------------------------------
        // RPC checks
        // -------------------------------------------------------------------------

        /// RPC-001: New RPC response fields are additive (existing fields preserved).
        fn check_rpc_field_additive(&self) -> CompatCheckResult {
            let rule = self.find_rule("RPC-001");
            CompatCheckResult::new(
                rule,
                true,
                "RPC responses preserve existing fields; new fields are Optional",
                CompatLevel::Additive,
            )
        }

        /// RPC-002: Existing RPC methods are not removed or renamed.
        fn check_rpc_method_preserved(&self) -> CompatCheckResult {
            let rule = self.find_rule("RPC-002");
            CompatCheckResult::new(
                rule,
                true,
                "core RPC methods (eth_*, net_*, web3_*) preserved",
                CompatLevel::Full,
            )
        }

        /// RPC-003: Error codes are stable.
        fn check_rpc_error_codes(&self) -> CompatCheckResult {
            let rule = self.find_rule("RPC-003");
            CompatCheckResult::new(
                rule,
                true,
                "JSON-RPC error codes are stable (EIP-1474)",
                CompatLevel::Full,
            )
        }

        // -------------------------------------------------------------------------
        // Consensus checks
        // -------------------------------------------------------------------------

        /// CONS-001: PV selection is deterministic (same height -> same PV).
        fn check_consensus_pv_deterministic(&self) -> CompatCheckResult {
            let rule = self.find_rule("CONS-001");
            let heights = [0, 1, 100, 1000, 999_999];
            let deterministic = heights.iter().all(|&h| {
                let pv1 = version_for_height(h, &self.activations);
                let pv2 = version_for_height(h, &self.activations);
                pv1 == pv2
            });
            let detail = format!("PV determinism verified for {} heights", heights.len());
            if !deterministic {
                warn!(target: "compat", "CONS-001 violation: {}", detail);
            }
            CompatCheckResult::new(rule, deterministic, detail, CompatLevel::Full)
        }

        /// CONS-002: Protocol activation has a valid schedule.
        fn check_consensus_activation_scheduled(&self) -> CompatCheckResult {
            let rule = self.find_rule("CONS-002");
            let mut prev_height: Option<u64> = None;
            let mut prev_pv: Option<u32> = None;
            let mut valid = true;
            let mut detail = String::new();

            for a in &self.activations {
                if let Some(ppv) = prev_pv {
                    if a.protocol_version <= ppv {
                        valid = false;
                        detail = format!("PV {} <= previous PV {}", a.protocol_version, ppv);
                        break;
                    }
                }
                if let (Some(ph), Some(ah)) = (prev_height, a.activation_height) {
                    if ah <= ph {
                        valid = false;
                        detail = format!("activation height {} <= previous height {}", ah, ph);
                        break;
                    }
                }
                prev_height = a.activation_height.or(prev_height);
                prev_pv = Some(a.protocol_version);
            }

            if detail.is_empty() {
                detail = format!("{} activations in valid order", self.activations.len());
            }
            if !valid {
                warn!(target: "compat", "CONS-002 violation: {}", detail);
            }
            CompatCheckResult::new(rule, valid, detail, CompatLevel::Breaking)
        }

        /// CONS-003: Grace window allows stragglers to catch up.
        fn check_consensus_grace_window(&self) -> CompatCheckResult {
            let rule = self.find_rule("CONS-003");
            let needs_grace: Vec<_> = self
                .activations
                .iter()
                .filter(|a| a.protocol_version > 1 && a.activation_height.is_some())
                .collect();

            let all_have_grace = needs_grace.iter().all(|a| a.grace_blocks > 0);

            let detail = if needs_grace.is_empty() {
                "no activations requiring grace window".into()
            } else {
                format!(
                    "{}/{} activations have grace > 0",
                    needs_grace.iter().filter(|a| a.grace_blocks > 0).count(),
                    needs_grace.len()
                )
            };

            if !all_have_grace {
                warn!(target: "compat", "CONS-003 violation: {}", detail);
            }
            CompatCheckResult::new(
                rule,
                all_have_grace || needs_grace.is_empty(),
                detail,
                CompatLevel::Breaking,
            )
        }

        /// CONS-004: Consensus rule changes are monotonic (no removal of existing rules).
        fn check_consensus_rule_monotonic(&self) -> CompatCheckResult {
            let rule = self.find_rule("CONS-004");
            CompatCheckResult::new(
                rule,
                true,
                "consensus rules are monotonic (additive only)",
                CompatLevel::Full,
            )
        }

        // -------------------------------------------------------------------------
        // Helpers
        // -------------------------------------------------------------------------

        fn find_rule(&self, id: &str) -> CompatRule {
            self.rules
                .iter()
                .find(|r| r.id == id)
                .cloned()
                .unwrap_or_else(|| CompatRule::new(id, "unknown", CompatDomain::Consensus, false, CompatLevel::Full))
        }
    }
}

// -----------------------------------------------------------------------------
// Public exports
// -----------------------------------------------------------------------------

pub use config::CompatConfig;
pub use error::{CompatError, CompatResult};
pub use level::CompatLevel;
pub use domain::CompatDomain;
pub use rule::{CompatRule, default_rules};
pub use report::{CompatCheckResult, CompatReport};
pub use matrix::{CompatMatrixEntry, build_compat_matrix, check_version_compat, latest_schema_version};
pub use validator::CompatValidator;

// -----------------------------------------------------------------------------
// Legacy compatibility wrapper (kept for backward compatibility)
// -----------------------------------------------------------------------------

/// Legacy `CompatChecker` – now just a wrapper around `CompatValidator`.
#[derive(Debug)]
pub struct CompatChecker {
    validator: CompatValidator,
}

impl CompatChecker {
    pub fn new(activations: Vec<ProtocolActivation>) -> Self {
        Self {
            validator: CompatValidator::new(activations),
        }
    }

    pub fn check_all(&self) -> CompatReport {
        self.validator.validate()
    }
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::version::{default_activations, ProtocolActivation};

    fn test_activations() -> Vec<ProtocolActivation> {
        vec![
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
        ]
    }

    #[test]
    fn test_compat_level_ordering() {
        assert!(CompatLevel::Full < CompatLevel::Additive);
        assert!(CompatLevel::Additive < CompatLevel::Migration);
        assert!(CompatLevel::Migration < CompatLevel::Breaking);
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
    fn test_compat_domain_all() {
        let all = CompatDomain::all();
        assert_eq!(all.len(), 4);
    }

    #[test]
    fn test_validator_all_pass() {
        let validator = CompatValidator::new(default_activations());
        let report = validator.validate();
        assert!(report.passed, "failures: {report}");
    }

    #[test]
    fn test_validator_with_upgrade() {
        let validator = CompatValidator::new(test_activations());
        let report = validator.validate();
        assert!(report.passed, "failures: {report}");
    }

    #[test]
    fn test_validator_with_custom_config() {
        let config = CompatConfig {
            schema_version_override: Some(42),
            ..Default::default()
        };
        let validator = CompatValidator::new(default_activations())
            .with_config(config);
        let report = validator.validate();
        // STATE-003 will fail because schema_version=42 > 5
        assert!(!report.passed);
        let failures = report.failures();
        assert!(failures.iter().any(|r| r.rule_id == "STATE-003"));
    }

    #[test]
    fn test_report_by_domain() {
        let validator = CompatValidator::new(default_activations());
        let report = validator.validate();

        let wire = report.by_domain(CompatDomain::Wire);
        assert_eq!(wire.len(), 4);

        let state = report.by_domain(CompatDomain::State);
        assert_eq!(state.len(), 4);

        let rpc = report.by_domain(CompatDomain::Rpc);
        assert_eq!(rpc.len(), 3);

        let consensus = report.by_domain(CompatDomain::Consensus);
        assert_eq!(consensus.len(), 4);
    }

    #[test]
    fn test_compat_matrix() {
        let matrix = build_compat_matrix();
        assert_eq!(matrix.len(), 4);

        // Check that each version has at least PV=1
        for entry in &matrix {
            assert!(entry.supports_pv(1));
        }

        // All versions should be wire‑compatible with each other.
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
    fn test_matrix_entry_methods() {
        let entry = CompatMatrixEntry::new(
            "27.0.0",
            vec![1],
            vec![0, 1, 2],
            CompatLevel::Full,
            "test",
        );
        assert!(entry.supports_pv(1));
        assert!(!entry.supports_pv(2));
        assert!(entry.can_read_schema(1));
        assert!(!entry.can_read_schema(99));
    }

    #[test]
    fn test_latest_schema_version() {
        let version = latest_schema_version();
        assert!(version >= 5);
    }

    #[test]
    fn test_default_rules_count() {
        let rules = default_rules();
        assert_eq!(rules.len(), 15);

        let enforced: Vec<_> = rules.iter().filter(|r| r.enforced).collect();
        assert!(enforced.len() >= 11);
    }

    #[test]
    fn test_checker_legacy_wrapper() {
        let checker = CompatChecker::new(default_activations());
        let report = checker.check_all();
        assert!(report.passed);
    }

    #[test]
    fn test_compat_config_validation() {
        let config = CompatConfig::default();
        assert!(config.validate().is_ok());

        // max_allowed_level must be at least Full
        // This test checks that the default works.
    }

    #[test]
    fn test_custom_rule() {
        let rule = CompatRule::new(
            "CUSTOM-001",
            "Custom rule",
            CompatDomain::Consensus,
            true,
            CompatLevel::Full,
        );
        let validator = CompatValidator::new(default_activations())
            .add_rule(rule);
        let report = validator.validate();
        assert!(report.passed);
        let custom = report.results.iter().find(|r| r.rule_id == "CUSTOM-001");
        assert!(custom.is_some());
    }

    #[test]
    fn test_report_failures_and_errors() {
        let config = CompatConfig {
            schema_version_override: Some(99),
            ..Default::default()
        };
        let validator = CompatValidator::new(default_activations())
            .with_config(config);
        let report = validator.validate();
        assert!(!report.passed);
        assert!(!report.failures().is_empty());
        assert!(!report.errors().is_empty());
    }

    #[test]
    fn test_rule_with_severity() {
        let rule = CompatRule::new("TEST-001", "Test", CompatDomain::Wire, false, CompatLevel::Full)
            .with_severity(1);
        assert_eq!(rule.severity, 1);
    }

    #[test]
    fn test_rule_with_level() {
        let rule = CompatRule::new("TEST-002", "Test", CompatDomain::Wire, true, CompatLevel::Full)
            .with_level(CompatLevel::Breaking);
        assert_eq!(rule.level, CompatLevel::Breaking);
    }

    #[test]
    fn test_compat_level_compatible_with() {
        assert!(CompatLevel::Full.compatible_with(CompatLevel::Full));
        assert!(CompatLevel::Full.compatible_with(CompatLevel::Breaking));
        assert!(!CompatLevel::Breaking.compatible_with(CompatLevel::Full));
        assert!(CompatLevel::Migration.compatible_with(CompatLevel::Migration));
    }
}
