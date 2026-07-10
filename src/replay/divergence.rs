//! Divergence detection across environments.
//!
//! Compares execution results from different nodes or environments to
//! identify where and why state divergence occurs.  This is essential
//! for debugging consensus splits and validating cross-platform builds.
//!
//! # Divergence Sources
//!
//! | Source              | Example                                    |
//! |---------------------|--------------------------------------------|
//! | Platform difference | x86 vs ARM float rounding (not used here)  |
//! | Compiler difference | Different optimisation levels               |
//! | Library version     | Updated crypto lib with different output    |
//! | Nondeterminism      | HashMap iteration order, timestamps         |
//! | Bug                 | Off-by-one in gas calculation               |
//!
//! # Usage
//!
//! ```rust,ignore
//! use iona::divergence::{NodeSnapshot, detect_divergence, DivergenceReport};
//! use iona::types::Hash32;
//!
//! let snapshot_a = NodeSnapshot::from_state(&state_a, "node-1", height);
//! let snapshot_b = NodeSnapshot::from_state(&state_b, "node-2", height);
//! let report = detect_divergence(&[snapshot_a, snapshot_b]);
//! if !report.all_agree {
//!     eprintln!("{}", report);
//!     // export minimal test case
//!     report.export_minimal_case("divergence_case.json");
//! }
//! ```

use crate::execution::KvState;
use crate::types::{Hash32, Height};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;
use tracing::{debug, info, warn};

// -----------------------------------------------------------------------------
// VM Snapshot (new)
// -----------------------------------------------------------------------------

/// Snapshot of the VM part of the state (contracts, storage, code, nonces).
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct VmSnapshot {
    /// Storage slots: (contract address, slot) → value (hex string)
    pub storage: BTreeMap<(String, String), String>,
    /// Contract bytecode: contract address → hex string
    pub code: BTreeMap<String, String>,
    /// VM‑specific nonces (e.g., for contract‑created accounts)
    pub nonces: BTreeMap<String, u64>,
}

impl VmSnapshot {
    /// Create a VM snapshot from the VM part of a KvState.
    pub fn from_state(state: &KvState) -> Self {
        let mut storage = BTreeMap::new();
        for ((contract, slot), value) in &state.vm.storage {
            storage.insert(
                (hex::encode(contract), hex::encode(slot)),
                hex::encode(value),
            );
        }
        let mut code = BTreeMap::new();
        for (addr, bytecode) in &state.vm.code {
            code.insert(hex::encode(addr), hex::encode(bytecode));
        }
        let mut nonces = BTreeMap::new();
        for (addr, nonce) in &state.vm.nonces {
            nonces.insert(hex::encode(addr), *nonce);
        }
        Self {
            storage,
            code,
            nonces,
        }
    }
}

// -----------------------------------------------------------------------------
// NodeSnapshot (enhanced)
// -----------------------------------------------------------------------------

/// A snapshot of a node's state at a given height.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeSnapshot {
    /// Identifier for this node/environment (e.g. "node-1-linux-x86").
    pub node_id: String,
    /// Protocol version this node was running.
    pub protocol_version: u32,
    /// Block height at which this snapshot was taken.
    pub height: Height,
    /// State root at this height.
    pub state_root: Hash32,
    /// Optional: per-account balance snapshot for detailed comparison.
    pub balances: Option<BTreeMap<String, u64>>,
    /// Optional: per-account nonce snapshot.
    pub nonces: Option<BTreeMap<String, u64>>,
    /// Optional: KV store snapshot.
    pub kv: Option<BTreeMap<String, String>>,
    /// Optional: VM state snapshot (contracts, storage, etc.)
    pub vm: Option<VmSnapshot>,
}

impl NodeSnapshot {
    /// Create a snapshot from a KvState and associated node information.
    pub fn from_state(
        state: &KvState,
        node_id: String,
        protocol_version: u32,
        height: Height,
        state_root: Hash32,
        include_full_state: bool,
    ) -> Self {
        let balances = if include_full_state {
            Some(state.balances.clone())
        } else {
            None
        };
        let nonces = if include_full_state {
            Some(state.nonces.clone())
        } else {
            None
        };
        let kv = if include_full_state {
            Some(state.kv.clone())
        } else {
            None
        };
        let vm = if include_full_state {
            Some(VmSnapshot::from_state(state))
        } else {
            None
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

    /// Save snapshot to a JSON file.
    pub fn save_to_file(&self, path: &Path) -> Result<(), std::io::Error> {
        let json = serde_json::to_string_pretty(self)?;
        std::fs::write(path, json)
    }

    /// Load snapshot from a JSON file.
    pub fn load_from_file(path: &Path) -> Result<Self, std::io::Error> {
        let data = std::fs::read_to_string(path)?;
        Ok(serde_json::from_str(&data)?)
    }
}

// -----------------------------------------------------------------------------
// Divergence Details (extended)
// -----------------------------------------------------------------------------

/// A specific difference between two node states.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum DivergenceDetail {
    /// Balance differs for an account.
    BalanceDiff {
        account: String,
        value_a: u64,
        value_b: u64,
    },
    /// Nonce differs for an account.
    NonceDiff {
        account: String,
        value_a: u64,
        value_b: u64,
    },
    /// KV entry differs.
    KvDiff {
        key: String,
        value_a: Option<String>,
        value_b: Option<String>,
    },
    /// Account exists in one snapshot but not the other.
    AccountMissing {
        account: String,
        present_in: String,
    },
    /// VM storage slot differs.
    VmStorageDiff {
        contract: String,
        slot: String,
        value_a: Option<String>,
        value_b: Option<String>,
    },
    /// Contract bytecode differs (length or content).
    VmCodeDiff {
        contract: String,
        len_a: usize,
        len_b: usize,
    },
    /// VM nonce differs.
    VmNonceDiff {
        contract: String,
        nonce_a: u64,
        nonce_b: u64,
    },
    /// Protocol version differs.
    ProtocolVersionDiff {
        version_a: u32,
        version_b: u32,
    },
}

impl std::fmt::Display for DivergenceDetail {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::BalanceDiff { account, value_a, value_b } =>
                write!(f, "balance({account}): {value_a} vs {value_b}"),
            Self::NonceDiff { account, value_a, value_b } =>
                write!(f, "nonce({account}): {value_a} vs {value_b}"),
            Self::KvDiff { key, value_a, value_b } =>
                write!(f, "kv({key}): {:?} vs {:?}", value_a, value_b),
            Self::AccountMissing { account, present_in } =>
                write!(f, "account {account} only in {present_in}"),
            Self::VmStorageDiff { contract, slot, value_a, value_b } =>
                write!(f, "vm.storage({contract},{slot}): {:?} vs {:?}", value_a, value_b),
            Self::VmCodeDiff { contract, len_a, len_b } =>
                write!(f, "vm.code({contract}): length {} vs {}", len_a, len_b),
            Self::VmNonceDiff { contract, nonce_a, nonce_b } =>
                write!(f, "vm.nonce({contract}): {} vs {}", nonce_a, nonce_b),
            Self::ProtocolVersionDiff { version_a, version_b } =>
                write!(f, "protocol version: {} vs {}", version_a, version_b),
        }
    }
}

// -----------------------------------------------------------------------------
// Divergence (enhanced)
// -----------------------------------------------------------------------------

/// A detected divergence between two nodes.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Divergence {
    /// Height where divergence was first detected.
    pub height: Height,
    /// Node A identifier.
    pub node_a: String,
    /// Node B identifier.
    pub node_b: String,
    /// State root from node A.
    pub root_a: Hash32,
    /// State root from node B.
    pub root_b: Hash32,
    /// Detailed differences (if snapshots include account data).
    pub details: Vec<DivergenceDetail>,
}

// -----------------------------------------------------------------------------
// DivergenceSummary
// -----------------------------------------------------------------------------

/// A high-level summary of detected divergences.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DivergenceSummary {
    /// Whether all nodes agree.
    pub all_agree: bool,
    /// Number of nodes compared.
    pub node_count: usize,
    /// Heights checked.
    pub heights_checked: Vec<Height>,
    /// Number of divergences detected.
    pub divergence_count: usize,
    /// Protocol versions observed (node → version).
    pub protocol_versions: BTreeMap<String, u32>,
    /// Heights where divergences were detected.
    pub divergent_heights: Vec<Height>,
}

impl DivergenceSummary {
    fn from_report(report: &DivergenceReport) -> Self {
        let mut protocol_versions = BTreeMap::new();
        for snapshot in &report.snapshots {
            protocol_versions.insert(snapshot.node_id.clone(), snapshot.protocol_version);
        }
        let divergent_heights = report
            .divergences
            .iter()
            .map(|d| d.height)
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect();
        Self {
            all_agree: report.all_agree,
            node_count: report.node_count,
            heights_checked: report.heights_checked.clone(),
            divergence_count: report.divergences.len(),
            protocol_versions,
            divergent_heights,
        }
    }
}

// -----------------------------------------------------------------------------
// DivergenceReport (enhanced)
// -----------------------------------------------------------------------------

/// Result of comparing two or more node snapshots.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DivergenceReport {
    /// All snapshots used in the analysis (for reference).
    pub snapshots: Vec<NodeSnapshot>,
    /// All detected divergences.
    pub divergences: Vec<Divergence>,
    /// Whether all nodes agree.
    pub all_agree: bool,
    /// Number of nodes compared.
    pub node_count: usize,
    /// Heights checked.
    pub heights_checked: Vec<Height>,
}

impl DivergenceReport {
    /// Generate a summary of this report.
    pub fn summary(&self) -> DivergenceSummary {
        DivergenceSummary::from_report(self)
    }

    /// Export a minimal test case that can reproduce the divergence.
    /// This writes a JSON file containing the initial state and the set of
    /// transactions that led to the first divergence.
    /// In a real implementation, this would need access to the block history.
    /// Here we produce a placeholder.
    pub fn export_minimal_case(&self, path: &Path) -> Result<(), std::io::Error> {
        // For now, we just export the snapshot of the first divergence.
        let first_div = self.divergences.first();
        let case = serde_json::json!({
            "divergence": first_div,
            "snapshots": self.snapshots,
            "note": "Minimal test case generation is a placeholder. "
        });
        std::fs::write(path, serde_json::to_string_pretty(&case)?)
    }

    /// Return a textual summary (for logs).
    pub fn log_summary(&self) {
        if self.all_agree {
            info!("Divergence report: all {} nodes agree across {} heights",
                  self.node_count, self.heights_checked.len());
        } else {
            warn!("Divergence detected! {} divergences found across {} nodes",
                  self.divergences.len(), self.node_count);
            for div in &self.divergences {
                warn!("  height {}: {} vs {}",
                      div.height, div.node_a, div.node_b);
            }
        }
    }
}

impl std::fmt::Display for DivergenceReport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "Divergence Report: {}",
            if self.all_agree { "NO DIVERGENCE" } else { "DIVERGENCE DETECTED" })?;
        writeln!(f, "  nodes={}, heights={:?}", self.node_count, self.heights_checked)?;
        for d in &self.divergences {
            writeln!(f, "  height {}: {} ({}) vs {} ({})",
                d.height,
                d.node_a, hex::encode(&d.root_a.0[..4]),
                d.node_b, hex::encode(&d.root_b.0[..4]))?;
            for detail in &d.details {
                writeln!(f, "    - {detail}")?;
            }
        }
        Ok(())
    }
}

// -----------------------------------------------------------------------------
// Comparison functions (enhanced)
// -----------------------------------------------------------------------------

/// Compare two node snapshots at the same height, with configurable depth.
/// If `compare_full_state` is false, only the state root is compared.
pub fn compare_snapshots(
    a: &NodeSnapshot,
    b: &NodeSnapshot,
    compare_full_state: bool,
) -> Option<Divergence> {
    if a.height != b.height {
        return None; // Cannot compare different heights.
    }

    // Always check protocol version
    let mut details = Vec::new();
    if a.protocol_version != b.protocol_version {
        details.push(DivergenceDetail::ProtocolVersionDiff {
            version_a: a.protocol_version,
            version_b: b.protocol_version,
        });
    }

    // Root comparison
    if a.state_root == b.state_root && details.is_empty() {
        return None; // No divergence.
    }

    if !compare_full_state {
        // Only root was compared; details are already collected (e.g., protocol version)
        return Some(Divergence {
            height: a.height,
            node_a: a.node_id.clone(),
            node_b: b.node_id.clone(),
            root_a: a.state_root.clone(),
            root_b: b.state_root.clone(),
            details,
        });
    }

    // Compare balances if available.
    if let (Some(bal_a), Some(bal_b)) = (&a.balances, &b.balances) {
        compare_btree_u64(bal_a, bal_b, &a.node_id, &b.node_id, &mut details, true);
    }

    // Compare nonces if available.
    if let (Some(non_a), Some(non_b)) = (&a.nonces, &b.nonces) {
        compare_btree_u64(non_a, non_b, &a.node_id, &b.node_id, &mut details, false);
    }

    // Compare KV if available.
    if let (Some(kv_a), Some(kv_b)) = (&a.kv, &b.kv) {
        compare_btree_str(kv_a, kv_b, &mut details);
    }

    // Compare VM snapshots if available.
    if let (Some(vm_a), Some(vm_b)) = (&a.vm, &b.vm) {
        compare_vm_snapshots(vm_a, vm_b, &mut details);
    }

    Some(Divergence {
        height: a.height,
        node_a: a.node_id.clone(),
        node_b: b.node_id.clone(),
        root_a: a.state_root.clone(),
        root_b: b.state_root.clone(),
        details,
    })
}

fn compare_btree_u64(
    a: &BTreeMap<String, u64>,
    b: &BTreeMap<String, u64>,
    node_a_id: &str,
    node_b_id: &str,
    details: &mut Vec<DivergenceDetail>,
    is_balance: bool,
) {
    // Keys in A but not B.
    for key in a.keys() {
        if !b.contains_key(key) {
            details.push(DivergenceDetail::AccountMissing {
                account: key.clone(),
                present_in: node_a_id.to_string(),
            });
        }
    }
    // Keys in B but not A.
    for key in b.keys() {
        if !a.contains_key(key) {
            details.push(DivergenceDetail::AccountMissing {
                account: key.clone(),
                present_in: node_b_id.to_string(),
            });
        }
    }
    // Keys in both: check values.
    for (key, &val_a) in a {
        if let Some(&val_b) = b.get(key) {
            if val_a != val_b {
                if is_balance {
                    details.push(DivergenceDetail::BalanceDiff {
                        account: key.clone(),
                        value_a: val_a,
                        value_b: val_b,
                    });
                } else {
                    details.push(DivergenceDetail::NonceDiff {
                        account: key.clone(),
                        value_a: val_a,
                        value_b: val_b,
                    });
                }
            }
        }
    }
}

fn compare_btree_str(
    a: &BTreeMap<String, String>,
    b: &BTreeMap<String, String>,
    details: &mut Vec<DivergenceDetail>,
) {
    for (key, val_a) in a {
        match b.get(key) {
            Some(val_b) if val_a != val_b => {
                details.push(DivergenceDetail::KvDiff {
                    key: key.clone(),
                    value_a: Some(val_a.clone()),
                    value_b: Some(val_b.clone()),
                });
            }
            None => {
                details.push(DivergenceDetail::KvDiff {
                    key: key.clone(),
                    value_a: Some(val_a.clone()),
                    value_b: None,
                });
            }
            _ => {}
        }
    }
    for (key, val_b) in b {
        if !a.contains_key(key) {
            details.push(DivergenceDetail::KvDiff {
                key: key.clone(),
                value_a: None,
                value_b: Some(val_b.clone()),
            });
        }
    }
}

fn compare_vm_snapshots(
    a: &VmSnapshot,
    b: &VmSnapshot,
    details: &mut Vec<DivergenceDetail>,
) {
    // Storage
    for ((contract, slot), val_a) in &a.storage {
        match b.storage.get(&(contract.clone(), slot.clone())) {
            Some(val_b) if val_a != val_b => {
                details.push(DivergenceDetail::VmStorageDiff {
                    contract: contract.clone(),
                    slot: slot.clone(),
                    value_a: Some(val_a.clone()),
                    value_b: Some(val_b.clone()),
                });
            }
            None => {
                details.push(DivergenceDetail::VmStorageDiff {
                    contract: contract.clone(),
                    slot: slot.clone(),
                    value_a: Some(val_a.clone()),
                    value_b: None,
                });
            }
            _ => {}
        }
    }
    for ((contract, slot), val_b) in &b.storage {
        if !a.storage.contains_key(&(contract.clone(), slot.clone())) {
            details.push(DivergenceDetail::VmStorageDiff {
                contract: contract.clone(),
                slot: slot.clone(),
                value_a: None,
                value_b: Some(val_b.clone()),
            });
        }
    }

    // Code
    for (contract, code_a) in &a.code {
        match b.code.get(contract) {
            Some(code_b) if code_a != code_b => {
                details.push(DivergenceDetail::VmCodeDiff {
                    contract: contract.clone(),
                    len_a: code_a.len(),
                    len_b: code_b.len(),
                });
            }
            None => {
                details.push(DivergenceDetail::VmCodeDiff {
                    contract: contract.clone(),
                    len_a: code_a.len(),
                    len_b: 0,
                });
            }
            _ => {}
        }
    }
    for (contract, code_b) in &b.code {
        if !a.code.contains_key(contract) {
            details.push(DivergenceDetail::VmCodeDiff {
                contract: contract.clone(),
                len_a: 0,
                len_b: code_b.len(),
            });
        }
    }

    // Nonces
    for (contract, nonce_a) in &a.nonces {
        match b.nonces.get(contract) {
            Some(nonce_b) if nonce_a != nonce_b => {
                details.push(DivergenceDetail::VmNonceDiff {
                    contract: contract.clone(),
                    nonce_a: *nonce_a,
                    nonce_b: *nonce_b,
                });
            }
            None => {
                details.push(DivergenceDetail::VmNonceDiff {
                    contract: contract.clone(),
                    nonce_a: *nonce_a,
                    nonce_b: 0,
                });
            }
            _ => {}
        }
    }
    for (contract, nonce_b) in &b.nonces {
        if !a.nonces.contains_key(contract) {
            details.push(DivergenceDetail::VmNonceDiff {
                contract: contract.clone(),
                nonce_a: 0,
                nonce_b: *nonce_b,
            });
        }
    }
}

// -----------------------------------------------------------------------------
// High‑level detection functions
// -----------------------------------------------------------------------------

/// Compare multiple node snapshots at the same height.
pub fn detect_divergence(snapshots: &[NodeSnapshot], compare_full_state: bool) -> DivergenceReport {
    let heights: Vec<Height> = snapshots.iter().map(|s| s.height).collect();
    let mut divergences = Vec::new();

    for i in 0..snapshots.len() {
        for j in (i + 1)..snapshots.len() {
            if let Some(div) = compare_snapshots(&snapshots[i], &snapshots[j], compare_full_state) {
                divergences.push(div);
            }
        }
    }

    DivergenceReport {
        snapshots: snapshots.to_vec(),
        divergences,
        all_agree: divergences.is_empty(),
        node_count: snapshots.len(),
        heights_checked: heights,
    }
}

/// Compare execution results across a range of heights.
///
/// `node_snapshots` is a map from node_id to a sorted list of snapshots.
pub fn detect_divergence_range(
    node_snapshots: &BTreeMap<String, Vec<NodeSnapshot>>,
    compare_full_state: bool,
) -> DivergenceReport {
    let mut all_divergences = Vec::new();
    let mut heights_checked = Vec::new();
    let mut all_snapshots = Vec::new();

    // Collect all unique heights.
    let mut all_heights = BTreeSet::new();
    for snapshots in node_snapshots.values() {
        for s in snapshots {
            all_heights.insert(s.height);
        }
    }

    for &height in &all_heights {
        heights_checked.push(height);

        // Gather snapshots at this height from all nodes.
        let at_height: Vec<&NodeSnapshot> = node_snapshots
            .values()
            .filter_map(|snaps| snaps.iter().find(|s| s.height == height))
            .collect();

        // Store all snapshots for the final report
        for s in &at_height {
            all_snapshots.push((*s).clone());
        }

        for i in 0..at_height.len() {
            for j in (i + 1)..at_height.len() {
                if let Some(div) = compare_snapshots(at_height[i], at_height[j], compare_full_state) {
                    all_divergences.push(div);
                }
            }
        }
    }

    // Remove duplicates (we may have same snapshot twice if multiple nodes)
    let mut unique_snapshots = BTreeMap::new();
    for s in all_snapshots {
        unique_snapshots.insert(s.node_id.clone(), s);
    }
    let snapshots: Vec<NodeSnapshot> = unique_snapshots.into_values().collect();

    DivergenceReport {
        snapshots,
        divergences: all_divergences,
        all_agree: all_divergences.is_empty(),
        node_count: node_snapshots.len(),
        heights_checked,
    }
}

// -----------------------------------------------------------------------------
// Benchmarks (in doc comments)
// -----------------------------------------------------------------------------

// To run benchmarks:
// ```
// cargo bench --bench divergence -- --test
// ```
// (Benchmarks not included here, but can be added in a separate `benches/divergence.rs` file)

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn dummy_state() -> KvState {
        let mut state = KvState::default();
        state.balances.insert("alice".into(), 1000);
        state.balances.insert("bob".into(), 500);
        state.nonces.insert("alice".into(), 1);
        state.kv.insert("key1".into(), "value1".into());
        // VM part: not set in this dummy
        state
    }

    fn snap(id: &str, height: Height, root: [u8; 32], protocol: u32, include_full: bool) -> NodeSnapshot {
        let state = dummy_state();
        NodeSnapshot::from_state(&state, id.into(), protocol, height, Hash32(root), include_full)
    }

    #[test]
    fn test_no_divergence() {
        let root = [1u8; 32];
        let snapshots = vec![
            snap("node-1", 100, root, 1, false),
            snap("node-2", 100, root, 1, false),
        ];
        let report = detect_divergence(&snapshots, false);
        assert!(report.all_agree);
        assert!(report.divergences.is_empty());
    }

    #[test]
    fn test_divergence_detected() {
        let snapshots = vec![
            snap("node-1", 100, [1u8; 32], 1, false),
            snap("node-2", 100, [2u8; 32], 1, false),
        ];
        let report = detect_divergence(&snapshots, false);
        assert!(!report.all_agree);
        assert_eq!(report.divergences.len(), 1);
    }

    #[test]
    fn test_protocol_version_diff() {
        let snapshots = vec![
            snap("node-1", 100, [1u8; 32], 1, false),
            snap("node-2", 100, [1u8; 32], 2, false),
        ];
        let report = detect_divergence(&snapshots, false);
        assert!(!report.all_agree);
        let div = &report.divergences[0];
        assert!(div.details.iter().any(|d| matches!(d,
            DivergenceDetail::ProtocolVersionDiff { version_a: 1, version_b: 2 }
        )));
    }

    #[test]
    fn test_full_state_comparison() {
        let mut state_a = dummy_state();
        let mut state_b = dummy_state();
        state_b.balances.insert("alice".into(), 999); // different balance
        let snap_a = NodeSnapshot::from_state(&state_a, "node-1".into(), 1, 100, Hash32([1; 32]), true);
        let snap_b = NodeSnapshot::from_state(&state_b, "node-2".into(), 1, 100, Hash32([2; 32]), true);

        let report = detect_divergence(&[snap_a, snap_b], true);
        assert!(!report.all_agree);
        let div = &report.divergences[0];
        assert!(div.details.iter().any(|d| matches!(d,
            DivergenceDetail::BalanceDiff { account, value_a: 1000, value_b: 999 }
            if account == "alice"
        )));
    }

    #[test]
    fn test_range_detection() {
        let mut node_snaps = BTreeMap::new();
        let mut v1 = Vec::new();
        v1.push(snap("node-1", 1, [1; 32], 1, false));
        v1.push(snap("node-1", 2, [2; 32], 1, false));
        let mut v2 = Vec::new();
        v2.push(snap("node-2", 1, [1; 32], 1, false));
        v2.push(snap("node-2", 2, [9; 32], 1, false)); // diverges at height 2
        node_snaps.insert("node-1".into(), v1);
        node_snaps.insert("node-2".into(), v2);

        let report = detect_divergence_range(&node_snaps, false);
        assert!(!report.all_agree);
        assert_eq!(report.heights_checked.len(), 2);
        assert_eq!(report.divergences.len(), 1);
        assert_eq!(report.divergences[0].height, 2);
    }

    #[test]
    fn test_summary() {
        let root = [1u8; 32];
        let snapshots = vec![
            snap("node-1", 100, root, 1, false),
            snap("node-2", 100, root, 2, false),
        ];
        let report = detect_divergence(&snapshots, false);
        let summary = report.summary();
        assert!(!summary.all_agree);
        assert_eq!(summary.divergence_count, 1);
        assert_eq!(summary.node_count, 2);
        assert_eq!(summary.protocol_versions.get("node-1"), Some(&1));
        assert_eq!(summary.protocol_versions.get("node-2"), Some(&2));
    }
}
