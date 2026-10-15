//! Divergence detection across environments.
//!
//! Compares execution results from different nodes or environments to
//! identify where and why state divergence occurs. Used for debugging
//! consensus splits and validating cross-platform builds.
//!
//! # Divergence sources
//!
//! | Source              | Example                                     |
//! |---------------------|---------------------------------------------|
//! | Platform difference | x86 vs ARM float rounding                   |
//! | Compiler difference | Different optimisation levels               |
//! | Library version     | Updated crypto lib with different output    |
//! | Nondeterminism      | HashMap iteration order, timestamps         |
//! | Bug                 | Off-by-one in gas calculation               |
//!
//! # Comparison contract
//!
//! [`detect_divergence`] compares snapshots **only at the same height**.
//! A snapshot whose height has no peer is reported as
//! [`DivergenceKind::HeightGap`] — the previous implementation silently
//! dropped such snapshots and could return `all_agree = true` for two
//! nodes at different heights.
//!
//! [`detect_divergence_range`] additionally reports nodes that are missing
//! a height that other nodes have reached.
//!
//! # Severity
//!
//! A [`Divergence`] carries a [`DivergenceKind`]:
//!
//! - [`DivergenceKind::StateRoot`] — the state roots differ. **Fatal.**
//! - [`DivergenceKind::Detail`] — roots agree but per-account data
//!   differs. This is a bug in the comparison harness or a stale snapshot.
//! - [`DivergenceKind::ProtocolVersion`] — informational; nodes on
//!   different protocol versions can legitimately have identical state.
//! - [`DivergenceKind::HeightGap`] — one or more nodes were not observed
//!   at a height the others reached.
//!
//! # Usage
//!
//! ```rust,ignore
//! use iona::divergence::{NodeSnapshot, detect_divergence, DivergenceReport};
//!
//! let snapshots = vec![snapshot_a, snapshot_b];
//! let report = detect_divergence(&snapshots, /* compare_full_state = */ true);
//! if !report.all_agree {
//!     eprintln!("{report}");
//!     report.save_to_file("divergence_report.json")?;
//! }
//! ```

use crate::execution::KvState;
use crate::types::{Hash32, Height};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;
use thiserror::Error;
use tracing::{debug, info, warn};

// ── Errors ────────────────────────────────────────────────────────────────

/// Errors from divergence-report I/O.
#[derive(Debug, Error)]
pub enum DivergenceError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),
}

// ── VM snapshot ───────────────────────────────────────────────────────────

/// Snapshot of the VM part of the state (contracts, storage, code, nonces).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct VmSnapshot {
    /// Storage slots: `(contract_hex, slot_hex)` → `value_hex`.
    pub storage: BTreeMap<(String, String), String>,
    /// Contract bytecode: `contract_hex` → `code_hex`.
    pub code: BTreeMap<String, String>,
    /// VM-specific nonces (e.g. for contract-created accounts).
    pub nonces: BTreeMap<String, u64>,
}

impl VmSnapshot {
    /// Capture the VM subsystem of `state`.
    #[must_use]
    pub fn from_state(state: &KvState) -> Self {
        let storage = state
            .vm
            .storage
            .iter()
            .map(|((c, s), v)| {
                ((hex::encode(c), hex::encode(s)), hex::encode(v))
            })
            .collect();
        let code = state
            .vm
            .code
            .iter()
            .map(|(a, b)| (hex::encode(a), hex::encode(b)))
            .collect();
        let nonces = state
            .vm
            .nonces
            .iter()
            .map(|(a, n)| (hex::encode(a), *n))
            .collect();
        Self { storage, code, nonces }
    }

    /// Number of storage slots, code entries, and nonces, in that order.
    #[must_use]
    pub fn sizes(&self) -> (usize, usize, usize) {
        (self.storage.len(), self.code.len(), self.nonces.len())
    }
}

// ── Node snapshot ─────────────────────────────────────────────────────────

/// A snapshot of a node's state at a given height.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NodeSnapshot {
    /// Identifier for this node/environment (e.g. `"node-1-linux-x86"`).
    pub node_id: String,
    /// Protocol version this node was running.
    pub protocol_version: u32,
    /// Block height at which this snapshot was taken.
    pub height: Height,
    /// State root at this height.
    pub state_root: Hash32,
    /// Optional per-account balance snapshot.
    pub balances: Option<BTreeMap<String, u64>>,
    /// Optional per-account nonce snapshot.
    pub nonces: Option<BTreeMap<String, u64>>,
    /// Optional KV store snapshot.
    pub kv: Option<BTreeMap<String, String>>,
    /// Optional VM state snapshot.
    pub vm: Option<VmSnapshot>,
}

impl NodeSnapshot {
    /// Build a snapshot from `state`.
    ///
    /// When `include_full_state` is `false`, only the state root and
    /// metadata are captured; the per-account maps are `None`, and
    /// [`detect_divergence`] can only compare roots.
    #[must_use]
    pub fn from_state(
        state: &KvState,
        node_id: String,
        protocol_version: u32,
        height: Height,
        state_root: Hash32,
        include_full_state: bool,
    ) -> Self {
        let (balances, nonces, kv, vm) = if include_full_state {
            (
                Some(state.balances.clone()),
                Some(state.nonces.clone()),
                Some(state.kv.clone()),
                Some(VmSnapshot::from_state(state)),
            )
        } else {
            (None, None, None, None)
        };

        Self {
            node_id,
            protocol_version,
            height,
            state_root,
            balances,
            nonces,
            kv,
            vm,
        }
    }

    /// Whether this snapshot carries per-account data.
    #[must_use]
    pub fn has_full_state(&self) -> bool {
        self.balances.is_some() || self.nonces.is_some() || self.kv.is_some() || self.vm.is_some()
    }

    /// Persist to a JSON file.
    pub fn save_to_file(&self, path: &Path) -> Result<(), DivergenceError> {
        let json = serde_json::to_string_pretty(self)?;
        std::fs::write(path, json)?;
        Ok(())
    }

    /// Load from a JSON file.
    pub fn load_from_file(path: &Path) -> Result<Self, DivergenceError> {
        let data = std::fs::read_to_string(path)?;
        Ok(serde_json::from_str(&data)?)
    }
}

impl std::fmt::Display for NodeSnapshot {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "NodeSnapshot({} @ height {}, root={}, proto={}, full={})",
            self.node_id,
            self.height,
            hex::encode(&self.state_root.0[..4]),
            self.protocol_version,
            self.has_full_state(),
        )
    }
}

// ── Divergence details ────────────────────────────────────────────────────

/// A specific difference between two node states.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum DivergenceDetail {
    /// Balance differs for an account.
    BalanceDiff { account: String, value_a: u64, value_b: u64 },
    /// Nonce differs for an account.
    NonceDiff { account: String, value_a: u64, value_b: u64 },
    /// KV entry differs.
    KvDiff {
        key: String,
        value_a: Option<String>,
        value_b: Option<String>,
    },
    /// Account exists in one snapshot but not the other.
    AccountMissing { account: String, present_in: String },
    /// VM storage slot differs.
    VmStorageDiff {
        contract: String,
        slot: String,
        value_a: Option<String>,
        value_b: Option<String>,
    },
    /// Contract bytecode differs.
    ///
    /// Carries both the length and a short digest of each bytecode so
    /// two same-length codes with different contents are distinguishable
    /// at a glance.
    VmCodeDiff {
        contract: String,
        len_a: usize,
        len_b: usize,
        digest_a: String,
        digest_b: String,
    },
    /// VM nonce differs.
    VmNonceDiff {
        contract: String,
        nonce_a: u64,
        nonce_b: u64,
    },
    /// Protocol version differs.
    ProtocolVersionDiff { version_a: u32, version_b: u32 },
}

impl std::fmt::Display for DivergenceDetail {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::BalanceDiff { account, value_a, value_b } => {
                write!(f, "balance({account}): {value_a} vs {value_b}")
            }
            Self::NonceDiff { account, value_a, value_b } => {
                write!(f, "nonce({account}): {value_a} vs {value_b}")
            }
            Self::KvDiff { key, value_a, value_b } => {
                write!(f, "kv({key}): {value_a:?} vs {value_b:?}")
            }
            Self::AccountMissing { account, present_in } => {
                write!(f, "account {account} only in {present_in}")
            }
            Self::VmStorageDiff { contract, slot, value_a, value_b } => {
                write!(f, "vm.storage({contract},{slot}): {value_a:?} vs {value_b:?}")
            }
            Self::VmCodeDiff { contract, len_a, len_b, digest_a, digest_b } => {
                write!(
                    f,
                    "vm.code({contract}): len {len_a}/{len_b}, digest {digest_a}/{digest_b}"
                )
            }
            Self::VmNonceDiff { contract, nonce_a, nonce_b } => {
                write!(f, "vm.nonce({contract}): {nonce_a} vs {nonce_b}")
            }
            Self::ProtocolVersionDiff { version_a, version_b } => {
                write!(f, "protocol version: {version_a} vs {version_b}")
            }
        }
    }
}

// ── Divergence ────────────────────────────────────────────────────────────

/// Severity of a divergence.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum DivergenceKind {
    /// Informational: nodes report different protocol versions, but the
    /// state is compatible.
    ProtocolVersion,
    /// One or more nodes were not observed at a height the others reached.
    HeightGap,
    /// Roots agree, but per-account data differs. Typically a comparison
    /// harness bug or a stale snapshot.
    Detail,
    /// State roots differ. **Fatal.**
    StateRoot,
}

impl std::fmt::Display for DivergenceKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ProtocolVersion => f.write_str("protocol-version"),
            Self::HeightGap => f.write_str("height-gap"),
            Self::Detail => f.write_str("detail"),
            Self::StateRoot => f.write_str("state-root"),
        }
    }
}

/// A detected divergence between two nodes (or a gap in coverage).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Divergence {
    /// Severity classification.
    pub kind: DivergenceKind,
    /// Height at which the divergence was detected.
    pub height: Height,
    /// Node A identifier.
    pub node_a: String,
    /// Node B identifier.
    pub node_b: String,
    /// State root from node A. Zero when `kind == HeightGap` and A is
    /// the side that is missing.
    pub root_a: Hash32,
    /// State root from node B. Zero when `kind == HeightGap` and B is
    /// the side that is missing.
    pub root_b: Hash32,
    /// Detailed differences. Empty for `HeightGap`.
    pub details: Vec<DivergenceDetail>,
}

// ── Summary ───────────────────────────────────────────────────────────────

/// High-level summary of detected divergences.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DivergenceSummary {
    pub all_agree: bool,
    pub node_count: usize,
    pub heights_checked: Vec<Height>,
    pub divergence_count: usize,
    /// Node → protocol version.
    pub protocol_versions: BTreeMap<String, u32>,
    /// Heights where a `StateRoot` divergence was detected.
    pub divergent_heights: Vec<Height>,
}

// ── Report ────────────────────────────────────────────────────────────────

/// Result of comparing two or more node snapshots.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DivergenceReport {
    /// All snapshots used in the analysis (for reference).
    pub snapshots: Vec<NodeSnapshot>,
    /// All detected divergences.
    pub divergences: Vec<Divergence>,
    /// Whether **all** nodes agree at every observed height and every
    /// node was observed at every height the others reached.
    pub all_agree: bool,
    /// Number of nodes compared.
    pub node_count: usize,
    /// Heights actually compared (deduplicated, sorted).
    pub heights_checked: Vec<Height>,
}

impl DivergenceReport {
    /// Build a summary from this report.
    #[must_use]
    pub fn summary(&self) -> DivergenceSummary {
        let protocol_versions = self
            .snapshots
            .iter()
            .map(|s| (s.node_id.clone(), s.protocol_version))
            .collect();
        let divergent_heights = self
            .divergences
            .iter()
            .filter(|d| d.kind == DivergenceKind::StateRoot)
            .map(|d| d.height)
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect();
        DivergenceSummary {
            all_agree: self.all_agree,
            node_count: self.node_count,
            heights_checked: self.heights_checked.clone(),
            divergence_count: self.divergences.len(),
            protocol_versions,
            divergent_heights,
        }
    }

    /// Whether any divergence of the given kind or worse exists.
    #[must_use]
    pub fn has_kind(&self, kind: DivergenceKind) -> bool {
        self.divergences.iter().any(|d| d.kind >= kind)
    }

    /// Persist the report to a JSON file.
    pub fn save_to_file(&self, path: &Path) -> Result<(), DivergenceError> {
        let json = serde_json::to_string_pretty(self)?;
        std::fs::write(path, json)?;
        Ok(())
    }

    /// Load a report from a JSON file.
    pub fn load_from_file(path: &Path) -> Result<Self, DivergenceError> {
        let data = std::fs::read_to_string(path)?;
        Ok(serde_json::from_str(&data)?)
    }

    /// Emit a structured log line summarising the report.
    pub fn log_summary(&self) {
        if self.all_agree {
            info!(
                nodes = self.node_count,
                heights = self.heights_checked.len(),
                "divergence report: all nodes agree"
            );
            return;
        }

        let fatal = self
            .divergences
            .iter()
            .filter(|d| d.kind == DivergenceKind::StateRoot)
            .count();
        let gaps = self
            .divergences
            .iter()
            .filter(|d| d.kind == DivergenceKind::HeightGap)
            .count();
        let details = self
            .divergences
            .iter()
            .filter(|d| d.kind == DivergenceKind::Detail)
            .count();
        let proto = self
            .divergences
            .iter()
            .filter(|d| d.kind == DivergenceKind::ProtocolVersion)
            .count();

        warn!(
            nodes = self.node_count,
            total = self.divergences.len(),
            state_root = fatal,
            height_gap = gaps,
            detail = details,
            protocol_version = proto,
            "divergence detected"
        );
        for div in &self.divergences {
            if div.kind == DivergenceKind::ProtocolVersion {
                debug!(
                    height = div.height,
                    a = %div.node_a,
                    b = %div.node_b,
                    kind = %div.kind,
                    "informational divergence"
                );
            } else {
                warn!(
                    height = div.height,
                    a = %div.node_a,
                    b = %div.node_b,
                    kind = %div.kind,
                    details = div.details.len(),
                    "divergence"
                );
            }
        }
    }
}

impl std::fmt::Display for DivergenceReport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(
            f,
            "Divergence Report: {}",
            if self.all_agree {
                "NO DIVERGENCE"
            } else {
                "DIVERGENCE DETECTED"
            }
        )?;
        writeln!(
            f,
            "  nodes={}, heights_checked={:?}",
            self.node_count, self.heights_checked
        )?;
        for d in &self.divergences {
            writeln!(
                f,
                "  [{}] height {}: {} ({}) vs {} ({})",
                d.kind,
                d.height,
                d.node_a,
                hex::encode(&d.root_a.0[..4]),
                d.node_b,
                hex::encode(&d.root_b.0[..4]),
            )?;
            for detail in &d.details {
                writeln!(f, "    - {detail}")?;
            }
        }
        Ok(())
    }
}

// ── Comparison ────────────────────────────────────────────────────────────

/// Compare two snapshots at the same height.
///
/// Returns `None` when the heights differ (the caller must decide how to
/// treat a height gap — see [`detect_divergence`]).
///
/// A `ProtocolVersionDiff` alone does **not** set `all_agree = false`:
/// the divergence is reported for visibility, but the caller can check
/// `report.has_kind(DivergenceKind::StateRoot)` to decide whether to abort.
#[must_use]
pub fn compare_snapshots(
    a: &NodeSnapshot,
    b: &NodeSnapshot,
    compare_full_state: bool,
) -> Option<Divergence> {
    if a.height != b.height {
        return None;
    }

    let mut details = Vec::new();
    if a.protocol_version != b.protocol_version {
        details.push(DivergenceDetail::ProtocolVersionDiff {
            version_a: a.protocol_version,
            version_b: b.protocol_version,
        });
    }

    // Roots first.
    let roots_match = a.state_root == b.state_root;
    if roots_match && details.is_empty() {
        return None;
    }

    // Classify before doing expensive per-account work.
    let kind = if !roots_match {
        DivergenceKind::StateRoot
    } else if !details.is_empty() {
        // Only protocol-version diff so far.
        DivergenceKind::ProtocolVersion
    } else {
        // Roots agree but full-state comparison may reveal something.
        DivergenceKind::Detail
    };

    // Detailed comparisons only when the caller asked for them **and**
    // we have the data.
    if compare_full_state {
        if let (Some(bal_a), Some(bal_b)) = (&a.balances, &b.balances) {
            compare_u64_maps(bal_a, bal_b, &a.node_id, &b.node_id, &mut details, true);
        }
        if let (Some(non_a), Some(non_b)) = (&a.nonces, &b.nonces) {
            compare_u64_maps(non_a, non_b, &a.node_id, &b.node_id, &mut details, false);
        }
        if let (Some(kv_a), Some(kv_b)) = (&a.kv, &b.kv) {
            compare_str_maps(kv_a, kv_b, &mut details);
        }
        if let (Some(vm_a), Some(vm_b)) = (&a.vm, &b.vm) {
            compare_vm_snapshots(vm_a, vm_b, &mut details);
        }
    }

    Some(Divergence {
        kind,
        height: a.height,
        node_a: a.node_id.clone(),
        node_b: b.node_id.clone(),
        root_a: a.state_root,
        root_b: b.state_root,
        details,
    })
}

fn compare_u64_maps(
    a: &BTreeMap<String, u64>,
    b: &BTreeMap<String, u64>,
    a_id: &str,
    b_id: &str,
    details: &mut Vec<DivergenceDetail>,
    is_balance: bool,
) {
    for key in a.keys() {
        if !b.contains_key(key) {
            details.push(DivergenceDetail::AccountMissing {
                account: key.clone(),
                present_in: a_id.to_string(),
            });
        }
    }
    for key in b.keys() {
        if !a.contains_key(key) {
            details.push(DivergenceDetail::AccountMissing {
                account: key.clone(),
                present_in: b_id.to_string(),
            });
        }
    }
    for (key, &va) in a {
        if let Some(&vb) = b.get(key) {
            if va != vb {
                details.push(if is_balance {
                    DivergenceDetail::BalanceDiff {
                        account: key.clone(),
                        value_a: va,
                        value_b: vb,
                    }
                } else {
                    DivergenceDetail::NonceDiff {
                        account: key.clone(),
                        value_a: va,
                        value_b: vb,
                    }
                });
            }
        }
    }
}

fn compare_str_maps(
    a: &BTreeMap<String, String>,
    b: &BTreeMap<String, String>,
    details: &mut Vec<DivergenceDetail>,
) {
    for (key, va) in a {
        match b.get(key) {
            Some(vb) if va != vb => details.push(DivergenceDetail::KvDiff {
                key: key.clone(),
                value_a: Some(va.clone()),
                value_b: Some(vb.clone()),
            }),
            None => details.push(DivergenceDetail::KvDiff {
                key: key.clone(),
                value_a: Some(va.clone()),
                value_b: None,
            }),
            _ => {}
        }
    }
    for (key, vb) in b {
        if !a.contains_key(key) {
            details.push(DivergenceDetail::KvDiff {
                key: key.clone(),
                value_a: None,
                value_b: Some(vb.clone()),
            });
        }
    }
}

fn compare_vm_snapshots(a: &VmSnapshot, b: &VmSnapshot, details: &mut Vec<DivergenceDetail>) {
    // Storage
    for ((c, s), va) in &a.storage {
        match b.storage.get(&(c.clone(), s.clone())) {
            Some(vb) if va != vb => details.push(DivergenceDetail::VmStorageDiff {
                contract: c.clone(),
                slot: s.clone(),
                value_a: Some(va.clone()),
                value_b: Some(vb.clone()),
            }),
            None => details.push(DivergenceDetail::VmStorageDiff {
                contract: c.clone(),
                slot: s.clone(),
                value_a: Some(va.clone()),
                value_b: None,
            }),
            _ => {}
        }
    }
    for ((c, s), vb) in &b.storage {
        if !a.storage.contains_key(&(c.clone(), s.clone())) {
            details.push(DivergenceDetail::VmStorageDiff {
                contract: c.clone(),
                slot: s.clone(),
                value_a: None,
                value_b: Some(vb.clone()),
            });
        }
    }

    // Code
    for (c, ca) in &a.code {
        let digest_a = short_digest(ca);
        match b.code.get(c) {
            Some(cb) if ca != cb => details.push(DivergenceDetail::VmCodeDiff {
                contract: c.clone(),
                len_a: ca.len(),
                len_b: cb.len(),
                digest_a,
                digest_b: short_digest(cb),
            }),
            None => details.push(DivergenceDetail::VmCodeDiff {
                contract: c.clone(),
                len_a: ca.len(),
                len_b: 0,
                digest_a,
                digest_b: String::new(),
            }),
            _ => {}
        }
    }
    for (c, cb) in &b.code {
        if !a.code.contains_key(c) {
            details.push(DivergenceDetail::VmCodeDiff {
                contract: c.clone(),
                len_a: 0,
                len_b: cb.len(),
                digest_a: String::new(),
                digest_b: short_digest(cb),
            });
        }
    }

    // Nonces
    for (c, &na) in &a.nonces {
        match b.nonces.get(c) {
            Some(&nb) if na != nb => details.push(DivergenceDetail::VmNonceDiff {
                contract: c.clone(),
                nonce_a: na,
                nonce_b: nb,
            }),
            None => details.push(DivergenceDetail::VmNonceDiff {
                contract: c.clone(),
                nonce_a: na,
                nonce_b: 0,
            }),
            _ => {}
        }
    }
    for (c, &nb) in &b.nonces {
        if !a.nonces.contains_key(c) {
            details.push(DivergenceDetail::VmNonceDiff {
                contract: c.clone(),
                nonce_a: 0,
                nonce_b: nb,
            });
        }
    }
}

/// Short digest of a string for display purposes. Not cryptographic.
fn short_digest(s: &str) -> String {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};
    let mut h = DefaultHasher::new();
    s.hash(&mut h);
    format!("{:08x}", h.finish() as u32)
}

// ── High-level detection ──────────────────────────────────────────────────

/// Compare multiple snapshots.
///
/// Snapshots are grouped by height. At each height, every pair is
/// compared; a height with a single snapshot produces a
/// [`DivergenceKind::HeightGap`] entry for each missing peer.
///
/// `all_agree` is `true` when the report contains **no** divergence of
/// any kind — including protocol-version and height-gap. Use
/// [`DivergenceReport::has_kind`] to distinguish informational
/// divergences from fatal ones.
#[must_use]
pub fn detect_divergence(
    snapshots: &[NodeSnapshot],
    compare_full_state: bool,
) -> DivergenceReport {
    if snapshots.is_empty() {
        return DivergenceReport {
            snapshots: Vec::new(),
            divergences: Vec::new(),
            all_agree: true,
            node_count: 0,
            heights_checked: Vec::new(),
        };
    }

    // Group by height.
    let mut by_height: BTreeMap<Height, Vec<&NodeSnapshot>> = BTreeMap::new();
    for s in snapshots {
        by_height.entry(s.height).or_default().push(s);
    }

    let heights_checked: Vec<Height> = by_height.keys().copied().collect();
    let mut divergences = Vec::new();

    for (&height, group) in &by_height {
        // Height gap: only one node (or none) at this height.
        if group.len() < 2 {
            for node in group {
                divergences.push(Divergence {
                    kind: DivergenceKind::HeightGap,
                    height,
                    node_a: node.node_id.clone(),
                    node_b: String::from("<no peer>"),
                    root_a: node.state_root,
                    root_b: Hash32::zero(),
                    details: Vec::new(),
                });
            }
        }

        // Pairwise comparison.
        for i in 0..group.len() {
            for j in (i + 1)..group.len() {
                if let Some(d) = compare_snapshots(group[i], group[j], compare_full_state) {
                    divergences.push(d);
                }
            }
        }
    }

    // Sort by (height, kind desc) so fatal divergences appear first.
    divergences.sort_by(|a, b| {
        a.height
            .cmp(&b.height)
            .then(b.kind.cmp(&a.kind))
            .then(a.node_a.cmp(&b.node_a))
            .then(a.node_b.cmp(&b.node_b))
    });

    let all_agree = divergences.is_empty();
    DivergenceReport {
        snapshots: snapshots.to_vec(),
        divergences,
        all_agree,
        node_count: snapshots.len(),
        heights_checked,
    }
}

/// Compare execution results across a range of heights.
///
/// `node_snapshots` maps `node_id` to a list of snapshots (each at a
/// distinct height). A node that is missing a height another node has
/// reached generates a [`DivergenceKind::HeightGap`] entry.
#[must_use]
pub fn detect_divergence_range(
    node_snapshots: &BTreeMap<String, Vec<NodeSnapshot>>,
    compare_full_state: bool,
) -> DivergenceReport {
    if node_snapshots.is_empty() {
        return DivergenceReport {
            snapshots: Vec::new(),
            divergences: Vec::new(),
            all_agree: true,
            node_count: 0,
            heights_checked: Vec::new(),
        };
    }

    // All heights any node reported.
    let mut all_heights: BTreeSet<Height> = BTreeSet::new();
    for snaps in node_snapshots.values() {
        for s in snaps {
            all_heights.insert(s.height);
        }
    }

    // Index snapshots by (node, height) for O(1) lookup.
    let mut index: BTreeMap<(&str, Height), &NodeSnapshot> = BTreeMap::new();
    for (node, snaps) in node_snapshots {
        for s in snaps {
            index.insert((node.as_str(), s.height), s);
        }
    }

    let mut divergences: Vec<Divergence> = Vec::new();
    let mut all_snapshots: Vec<NodeSnapshot> = Vec::new();
    let mut heights_checked: Vec<Height> = Vec::new();

    for &height in &all_heights {
        heights_checked.push(height);

        // Nodes present at this height.
        let present: Vec<&NodeSnapshot> = node_snapshots
            .keys()
            .filter_map(|node| index.get(&(node.as_str(), height)).copied())
            .collect();

        for s in &present {
            all_snapshots.push((*s).clone());
        }

        // Height gaps: nodes that exist in the map but not at this height.
        let present_ids: BTreeSet<&str> = present.iter().map(|s| s.node_id.as_str()).collect();
        for node in node_snapshots.keys() {
            if !present_ids.contains(node.as_str()) {
                divergences.push(Divergence {
                    kind: DivergenceKind::HeightGap,
                    height,
                    node_a: node.clone(),
                    node_b: String::from("<no snapshot>"),
                    root_a: Hash32::zero(),
                    root_b: Hash32::zero(),
                    details: Vec::new(),
                });
            }
        }

        // Pairwise comparison among those present.
        for i in 0..present.len() {
            for j in (i + 1)..present.len() {
                if let Some(d) = compare_snapshots(present[i], present[j], compare_full_state) {
                    divergences.push(d);
                }
            }
        }
    }

    divergences.sort_by(|a, b| {
        a.height
            .cmp(&b.height)
            .then(b.kind.cmp(&a.kind))
            .then(a.node_a.cmp(&b.node_a))
            .then(a.node_b.cmp(&b.node_b))
    });

    // Deduplicate snapshots by node id (keep the last seen).
    let mut unique: BTreeMap<String, NodeSnapshot> = BTreeMap::new();
    for s in all_snapshots {
        unique.insert(s.node_id.clone(), s);
    }

    let all_agree = divergences.is_empty();
    DivergenceReport {
        snapshots: unique.into_values().collect(),
        divergences,
        all_agree,
        node_count: node_snapshots.len(),
        heights_checked,
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn dummy_state() -> KvState {
        let mut state = KvState::default();
        state.balances.insert("alice".into(), 1000);
        state.balances.insert("bob".into(), 500);
        state.nonces.insert("alice".into(), 1);
        state.kv.insert("key1".into(), "value1".into());
        state
    }

    fn snap(
        id: &str,
        height: Height,
        root: [u8; 32],
        protocol: u32,
        include_full: bool,
    ) -> NodeSnapshot {
        let state = dummy_state();
        NodeSnapshot::from_state(&state, id.into(), protocol, height, Hash32(root), include_full)
    }

    // ── Basic ───────────────────────────────────────────────────────────

    #[test]
    fn no_divergence() {
        let s = vec![
            snap("node-1", 100, [1; 32], 1, false),
            snap("node-2", 100, [1; 32], 1, false),
        ];
        let r = detect_divergence(&s, false);
        assert!(r.all_agree);
        assert!(r.divergences.is_empty());
        assert_eq!(r.heights_checked, vec![100]);
    }

    #[test]
    fn state_root_divergence_detected() {
        let s = vec![
            snap("node-1", 100, [1; 32], 1, false),
            snap("node-2", 100, [2; 32], 1, false),
        ];
        let r = detect_divergence(&s, false);
        assert!(!r.all_agree);
        assert_eq!(r.divergences.len(), 1);
        assert_eq!(r.divergences[0].kind, DivergenceKind::StateRoot);
        assert!(r.has_kind(DivergenceKind::StateRoot));
    }

    #[test]
    fn protocol_version_diff_is_informational() {
        let s = vec![
            snap("node-1", 100, [1; 32], 1, false),
            snap("node-2", 100, [1; 32], 2, false),
        ];
        let r = detect_divergence(&s, false);
        assert!(!r.all_agree);
        assert_eq!(r.divergences.len(), 1);
        assert_eq!(r.divergences[0].kind, DivergenceKind::ProtocolVersion);
        assert!(!r.has_kind(DivergenceKind::StateRoot));
    }

    // ── Height gap (regression) ─────────────────────────────────────────

    #[test]
    fn different_heights_produce_height_gap_not_silent_agreement() {
        // Regression: the previous implementation silently skipped
        // snapshots at different heights and returned `all_agree = true`
        // when only one node was observed at each height.
        let s = vec![
            snap("node-1", 100, [1; 32], 1, false),
            snap("node-2", 200, [2; 32], 1, false),
        ];
        let r = detect_divergence(&s, false);
        assert!(!r.all_agree, "height gap must not be reported as agreement");
        assert_eq!(r.divergences.len(), 2, "one gap per node");
        for d in &r.divergences {
            assert_eq!(d.kind, DivergenceKind::HeightGap);
        }
        assert_eq!(r.heights_checked, vec![100, 200]);
    }

    #[test]
    fn single_snapshot_at_a_height_produces_gap() {
        let s = vec![
            snap("node-1", 100, [1; 32], 1, false),
            snap("node-2", 100, [1; 32], 1, false),
            snap("node-3", 200, [9; 32], 1, false),
        ];
        let r = detect_divergence(&s, false);
        assert!(!r.all_agree);
        let gaps: Vec<&Divergence> = r
            .divergences
            .iter()
            .filter(|d| d.kind == DivergenceKind::HeightGap)
            .collect();
        assert_eq!(gaps.len(), 1);
        assert_eq!(gaps[0].height, 200);
        assert_eq!(gaps[0].node_a, "node-3");
    }

    #[test]
    fn single_snapshot_report_is_empty_and_agreeing() {
        let s = vec![snap("node-1", 100, [1; 32], 1, false)];
        let r = detect_divergence(&s, false);
        // Only one node total: no peers means no comparison, but the
        // single node is also not a "gap" (nothing to be missing from).
        assert!(r.all_agree);
        assert_eq!(r.divergences.len(), 0);
    }

    #[test]
    fn empty_report_is_agreeing() {
        let r = detect_divergence(&[], false);
        assert!(r.all_agree);
        assert_eq!(r.node_count, 0);
    }

    // ── Full-state comparison ───────────────────────────────────────────

    #[test]
    fn full_state_comparison_reports_balance_diff() {
        let state_a = dummy_state();
        let mut state_b = dummy_state();
        state_b.balances.insert("alice".into(), 999);

        let snap_a =
            NodeSnapshot::from_state(&state_a, "node-1".into(), 1, 100, Hash32([1; 32]), true);
        let snap_b =
            NodeSnapshot::from_state(&state_b, "node-2".into(), 1, 100, Hash32([2; 32]), true);

        let r = detect_divergence(&[snap_a, snap_b], true);
        assert!(!r.all_agree);
        assert_eq!(r.divergences[0].kind, DivergenceKind::StateRoot);
        assert!(r.divergences[0].details.iter().any(|d| matches!(
            d,
            DivergenceDetail::BalanceDiff { account, value_a: 1000, value_b: 999 }
            if account == "alice"
        )));
    }

    // ── Range detection ─────────────────────────────────────────────────

    #[test]
    fn range_detects_divergence_at_specific_height() {
        let mut nodes = BTreeMap::new();
        nodes.insert(
            "node-1".into(),
            vec![
                snap("node-1", 1, [1; 32], 1, false),
                snap("node-1", 2, [2; 32], 1, false),
            ],
        );
        nodes.insert(
            "node-2".into(),
            vec![
                snap("node-2", 1, [1; 32], 1, false),
                snap("node-2", 2, [9; 32], 1, false),
            ],
        );

        let r = detect_divergence_range(&nodes, false);
        assert!(!r.all_agree);
        assert_eq!(r.heights_checked, vec![1, 2]);
        // Only height 2 diverges (root mismatch).
        let fatal: Vec<_> = r
            .divergences
            .iter()
            .filter(|d| d.kind == DivergenceKind::StateRoot)
            .collect();
        assert_eq!(fatal.len(), 1);
        assert_eq!(fatal[0].height, 2);
    }

    #[test]
    fn range_detects_missing_height() {
        // node-1 reached height 3; node-2 stopped at 2.
        let mut nodes = BTreeMap::new();
        nodes.insert(
            "node-1".into(),
            vec![
                snap("node-1", 1, [1; 32], 1, false),
                snap("node-1", 2, [2; 32], 1, false),
                snap("node-1", 3, [3; 32], 1, false),
            ],
        );
        nodes.insert(
            "node-2".into(),
            vec![
                snap("node-2", 1, [1; 32], 1, false),
                snap("node-2", 2, [2; 32], 1, false),
            ],
        );

        let r = detect_divergence_range(&nodes, false);
        assert!(!r.all_agree);
        let gaps: Vec<_> = r
            .divergences
            .iter()
            .filter(|d| d.kind == DivergenceKind::HeightGap && d.height == 3)
            .collect();
        assert_eq!(gaps.len(), 1);
        assert_eq!(gaps[0].node_a, "node-2");
    }

    // ── Summary ─────────────────────────────────────────────────────────

    #[test]
    fn summary_captures_metadata() {
        let s = vec![
            snap("node-1", 100, [1; 32], 1, false),
            snap("node-2", 100, [1; 32], 2, false),
        ];
        let r = detect_divergence(&s, false);
        let summary = r.summary();
        assert!(!summary.all_agree);
        assert_eq!(summary.divergence_count, 1);
        assert_eq!(summary.node_count, 2);
        assert_eq!(summary.protocol_versions.get("node-1"), Some(&1));
        assert_eq!(summary.protocol_versions.get("node-2"), Some(&2));
        assert_eq!(summary.divergent_heights, Vec::<u64>::new()); // only proto diff
    }

    #[test]
    fn summary_reports_only_state_root_heights() {
        let s = vec![
            snap("node-1", 100, [1; 32], 1, false),
            snap("node-2", 100, [2; 32], 2, false),
        ];
        let r = detect_divergence(&s, false);
        let summary = r.summary();
        assert_eq!(summary.divergent_heights, vec![100]);
    }

    // ── Kind ordering ───────────────────────────────────────────────────

    #[test]
    fn has_kind_respects_severity_ordering() {
        let s = vec![
            snap("node-1", 100, [1; 32], 1, false),
            snap("node-2", 100, [2; 32], 1, false),
        ];
        let r = detect_divergence(&s, false);
        assert!(r.has_kind(DivergenceKind::StateRoot));
        assert!(r.has_kind(DivergenceKind::Detail)); // StateRoot >= Detail
        assert!(r.has_kind(DivergenceKind::ProtocolVersion)); // >= everything
    }

    #[test]
    fn protocol_version_only_does_not_satisfy_state_root_query() {
        let s = vec![
            snap("node-1", 100, [1; 32], 1, false),
            snap("node-2", 100, [1; 32], 2, false),
        ];
        let r = detect_divergence(&s, false);
        assert!(!r.has_kind(DivergenceKind::StateRoot));
        assert!(r.has_kind(DivergenceKind::ProtocolVersion));
    }

    // ── VM code digest ──────────────────────────────────────────────────

    #[test]
    fn vm_code_diff_includes_digests() {
        use std::collections::BTreeMap;
        let mut va = VmSnapshot::default();
        va.code.insert("c1".into(), "deadbeef".into());
        let mut vb = VmSnapshot::default();
        vb.code.insert("c1".into(), "deadbeeffeed".into());

        let mut details = Vec::new();
        compare_vm_snapshots(&va, &vb, &mut details);

        let diff = details
            .iter()
            .find_map(|d| match d {
                DivergenceDetail::VmCodeDiff {
                    len_a,
                    len_b,
                    digest_a,
                    digest_b,
                    ..
                } => Some((*len_a, *len_b, digest_a.clone(), digest_b.clone())),
                _ => None,
            })
            .expect("VmCodeDiff not produced");
        assert_eq!(diff.0, 8);
        assert_eq!(diff.1, 12);
        assert!(!diff.2.is_empty());
        assert!(!diff.3.is_empty());
        assert_ne!(diff.2, diff.3);
    }

    #[test]
    fn vm_code_diff_same_length_different_content() {
        let mut va = VmSnapshot::default();
        va.code.insert("c".into(), "aaaaaaaa".into());
        let mut vb = VmSnapshot::default();
        vb.code.insert("c".into(), "bbbbbbbb".into());

        let mut details = Vec::new();
        compare_vm_snapshots(&va, &vb, &mut details);
        let diff = details
            .iter()
            .find_map(|d| match d {
                DivergenceDetail::VmCodeDiff {
                    len_a,
                    len_b,
                    digest_a,
                    digest_b,
                    ..
                } => Some((*len_a, *len_b, digest_a.clone(), digest_b.clone())),
                _ => None,
            })
            .unwrap();
        assert_eq!(diff.0, diff.1, "lengths should match");
        assert_ne!(diff.2, diff.3, "digests must differ");
    }

    // ── Display / snapshot helpers ──────────────────────────────────────

    #[test]
    fn snapshot_display_includes_key_fields() {
        let s = snap("node-1", 42, [0xAB; 32], 7, false);
        let text = format!("{s}");
        assert!(text.contains("node-1"));
        assert!(text.contains("height 42"));
        assert!(text.contains("proto=7"));
    }

    #[test]
    fn snapshot_has_full_state_flag() {
        assert!(!snap("n", 1, [0; 32], 1, false).has_full_state());
        assert!(snap("n", 1, [0; 32], 1, true).has_full_state());
    }

    #[test]
    fn report_display_lists_each_divergence() {
        let s = vec![
            snap("node-1", 100, [1; 32], 1, false),
            snap("node-2", 100, [2; 32], 1, false),
        ];
        let text = format!("{}", detect_divergence(&s, false));
        assert!(text.contains("DIVERGENCE DETECTED"));
        assert!(text.contains("state-root"));
        assert!(text.contains("node-1"));
        assert!(text.contains("node-2"));
    }

    // ── Determinism of ordering ─────────────────────────────────────────

    #[test]
    fn divergences_are_sorted_by_height_then_kind() {
        // Heights: 100 (proto diff), 200 (state-root diff), 300 (proto diff).
        let s = vec![
            snap("a", 100, [1; 32], 1, false),
            snap("b", 100, [1; 32], 2, false),
            snap("a", 200, [3; 32], 1, false),
            snap("b", 200, [4; 32], 1, false),
            snap("a", 300, [5; 32], 1, false),
            snap("b", 300, [5; 32], 2, false),
        ];
        let r = detect_divergence(&s, false);
        let heights: Vec<_> = r.divergences.iter().map(|d| d.height).collect();
        let mut sorted = heights.clone();
        sorted.sort();
        assert_eq!(heights, sorted, "divergences should be height-sorted");
    }
}
