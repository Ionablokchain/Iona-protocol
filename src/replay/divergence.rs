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
//! # Serialisation
//!
//! Snapshots and divergence reports can be serialised to JSON or bincode
//! for storage, sharing, and later analysis.

use crate::types::{Hash32, Height};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashSet};
use std::fmt;
use std::fs::File;
use std::io::{BufReader, BufWriter};
use std::path::Path;
use thiserror::Error;
use tracing::{debug, info, warn};

// -----------------------------------------------------------------------------
// Errors
// -----------------------------------------------------------------------------

/// Errors that can occur during divergence detection.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum ReplayError {
    #[error("height mismatch: cannot compare snapshots at {0} and {1}")]
    HeightMismatch(Height, Height),
    #[error("missing snapshot for node '{0}' at height {1}")]
    MissingSnapshot(String, Height),
    #[error("inconsistent snapshot data: {0}")]
    InconsistentData(String),
    #[error("I/O error: {0}")]
    Io(String),
    #[error("serialisation error: {0}")]
    Serialisation(String),
    #[error("invalid snapshot format: {0}")]
    InvalidFormat(String),
    #[error("divergence already detected: {0}")]
    AlreadyDiverged(String),
}

pub type ReplayResult<T> = Result<T, ReplayError>;

// -----------------------------------------------------------------------------
// Snapshot and Divergence types
// -----------------------------------------------------------------------------

/// A snapshot of a node's state at a given height.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct NodeSnapshot {
    /// Identifier for this node/environment (e.g. "node-1-linux-x86").
    pub node_id: String,
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
    /// Optional: account code hashes (for smart contract divergence).
    pub code_hashes: Option<BTreeMap<String, Hash32>>,
    /// Optional: storage entries (by account and slot).
    pub storage: Option<BTreeMap<(String, String), String>>,
    /// Optional: recent transaction receipts (for execution divergence).
    pub receipts: Option<Vec<String>>,
    /// Optional: recent logs.
    pub logs: Option<Vec<String>>,
    /// Optional: timestamp when snapshot was taken.
    pub snapshot_time: Option<u64>,
    /// Optional: node version.
    pub node_version: Option<String>,
}

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
    /// Optional: timestamp when divergence was detected.
    pub detection_time: Option<u64>,
}

/// A specific difference between two node states.
#[derive(Debug, Clone, Serialize, Deserialize)]
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
    /// Code hash differs for an account.
    CodeHashDiff {
        account: String,
        hash_a: Option<Hash32>,
        hash_b: Option<Hash32>,
    },
    /// Storage value differs for an account+slot.
    StorageDiff {
        account: String,
        slot: String,
        value_a: Option<String>,
        value_b: Option<String>,
    },
    /// Receipt differs (by index or hash).
    ReceiptDiff {
        index: usize,
        receipt_a: String,
        receipt_b: String,
    },
    /// Log differs.
    LogDiff {
        index: usize,
        log_a: String,
        log_b: String,
    },
}

impl fmt::Display for DivergenceDetail {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::BalanceDiff {
                account,
                value_a,
                value_b,
            } => write!(f, "balance({account}): {value_a} vs {value_b}"),
            Self::NonceDiff {
                account,
                value_a,
                value_b,
            } => write!(f, "nonce({account}): {value_a} vs {value_b}"),
            Self::KvDiff {
                key,
                value_a,
                value_b,
            } => write!(f, "kv({key}): {:?} vs {:?}", value_a, value_b),
            Self::AccountMissing {
                account,
                present_in,
            } => write!(f, "account {account} only in {present_in}"),
            Self::CodeHashDiff {
                account,
                hash_a,
                hash_b,
            } => write!(
                f,
                "code_hash({account}): {:?} vs {:?}",
                hash_a.as_ref().map(|h| hex::encode(&h.0[..4])),
                hash_b.as_ref().map(|h| hex::encode(&h.0[..4]))
            ),
            Self::StorageDiff {
                account,
                slot,
                value_a,
                value_b,
            } => write!(
                f,
                "storage({account}, {slot}): {:?} vs {:?}",
                value_a, value_b
            ),
            Self::ReceiptDiff {
                index,
                receipt_a,
                receipt_b,
            } => write!(f, "receipt[{index}]: {receipt_a} vs {receipt_b}"),
            Self::LogDiff {
                index,
                log_a,
                log_b,
            } => write!(f, "log[{index}]: {log_a} vs {log_b}"),
        }
    }
}

/// Result of comparing two or more node snapshots.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DivergenceReport {
    /// All detected divergences.
    pub divergences: Vec<Divergence>,
    /// Whether all nodes agree.
    pub all_agree: bool,
    /// Number of nodes compared.
    pub node_count: usize,
    /// Heights checked.
    pub heights_checked: Vec<Height>,
    /// Optional: time when report was generated.
    pub report_time: Option<u64>,
}

impl fmt::Display for DivergenceReport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
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
            "  nodes={}, heights={:?}",
            self.node_count, self.heights_checked
        )?;
        for d in &self.divergences {
            writeln!(
                f,
                "  height {}: {} ({}) vs {} ({})",
                d.height,
                d.node_a,
                hex::encode(&d.root_a.0[..4]),
                d.node_b,
                hex::encode(&d.root_b.0[..4])
            )?;
            for detail in &d.details {
                writeln!(f, "    - {detail}")?;
            }
        }
        Ok(())
    }
}

// -----------------------------------------------------------------------------
// Comparison functions
// -----------------------------------------------------------------------------

/// Compare two node snapshots at the same height.
///
/// Returns `Ok(Some(Divergence))` if snapshots differ,
/// `Ok(None)` if they are identical,
/// and `Err` if heights mismatch.
pub fn compare_snapshots(a: &NodeSnapshot, b: &NodeSnapshot) -> ReplayResult<Option<Divergence>> {
    if a.height != b.height {
        return Err(ReplayError::HeightMismatch(a.height, b.height));
    }

    if a.state_root == b.state_root {
        // Quick path: if roots match, we can still check deeper (e.g., balances might differ
        // but root could match due to same trie? In practice, if root matches, all state
        // should match in a deterministic system, but we still allow deeper checks).
        // We'll still check if there are any differences in optional data.
        if snapshots_fully_equal(a, b) {
            return Ok(None);
        }
        // Root matches but optional data differs – this is a consistency issue.
        // We'll still report as divergence.
    }

    let mut details = Vec::new();

    // Compare balances if both are present.
    compare_balances(a, b, &mut details);
    compare_nonces(a, b, &mut details);
    compare_kv(a, b, &mut details);
    compare_code_hashes(a, b, &mut details);
    compare_storage(a, b, &mut details);
    compare_receipts(a, b, &mut details);
    compare_logs(a, b, &mut details);

    Ok(Some(Divergence {
        height: a.height,
        node_a: a.node_id.clone(),
        node_b: b.node_id.clone(),
        root_a: a.state_root,
        root_b: b.state_root,
        details,
        detection_time: None,
    }))
}

/// Helper: check if two snapshots are fully equal (all optional fields match).
fn snapshots_fully_equal(a: &NodeSnapshot, b: &NodeSnapshot) -> bool {
    if a.node_id != b.node_id || a.height != b.height || a.state_root != b.state_root {
        return false;
    }
    if a.balances != b.balances
        || a.nonces != b.nonces
        || a.kv != b.kv
        || a.code_hashes != b.code_hashes
        || a.storage != b.storage
        || a.receipts != b.receipts
        || a.logs != b.logs
        || a.node_version != b.node_version
    {
        return false;
    }
    true
}

fn compare_balances(a: &NodeSnapshot, b: &NodeSnapshot, details: &mut Vec<DivergenceDetail>) {
    match (&a.balances, &b.balances) {
        (Some(bal_a), Some(bal_b)) => {
            compare_btree_u64(bal_a, bal_b, &a.node_id, &b.node_id, details, true);
        }
        (Some(_), None) => {
            // One has balances, the other doesn't – we can't produce per‑account diffs.
            // We'll add a marker.
            details.push(DivergenceDetail::KvDiff {
                key: "balances".to_string(),
                value_a: Some("present".to_string()),
                value_b: None,
            });
        }
        (None, Some(_)) => {
            details.push(DivergenceDetail::KvDiff {
                key: "balances".to_string(),
                value_a: None,
                value_b: Some("present".to_string()),
            });
        }
        (None, None) => {}
    }
}

fn compare_nonces(a: &NodeSnapshot, b: &NodeSnapshot, details: &mut Vec<DivergenceDetail>) {
    match (&a.nonces, &b.nonces) {
        (Some(non_a), Some(non_b)) => {
            compare_btree_u64(non_a, non_b, &a.node_id, &b.node_id, details, false);
        }
        (Some(_), None) => {
            details.push(DivergenceDetail::KvDiff {
                key: "nonces".to_string(),
                value_a: Some("present".to_string()),
                value_b: None,
            });
        }
        (None, Some(_)) => {
            details.push(DivergenceDetail::KvDiff {
                key: "nonces".to_string(),
                value_a: None,
                value_b: Some("present".to_string()),
            });
        }
        (None, None) => {}
    }
}

fn compare_kv(a: &NodeSnapshot, b: &NodeSnapshot, details: &mut Vec<DivergenceDetail>) {
    match (&a.kv, &b.kv) {
        (Some(kv_a), Some(kv_b)) => {
            compare_btree_str(kv_a, kv_b, details);
        }
        (Some(_), None) => {
            details.push(DivergenceDetail::KvDiff {
                key: "kv".to_string(),
                value_a: Some("present".to_string()),
                value_b: None,
            });
        }
        (None, Some(_)) => {
            details.push(DivergenceDetail::KvDiff {
                key: "kv".to_string(),
                value_a: None,
                value_b: Some("present".to_string()),
            });
        }
        (None, None) => {}
    }
}

fn compare_code_hashes(a: &NodeSnapshot, b: &NodeSnapshot, details: &mut Vec<DivergenceDetail>) {
    match (&a.code_hashes, &b.code_hashes) {
        (Some(hash_a), Some(hash_b)) => {
            let all_accounts: HashSet<String> =
                hash_a.keys().chain(hash_b.keys()).cloned().collect();
            for account in all_accounts {
                let val_a = hash_a.get(&account);
                let val_b = hash_b.get(&account);
                if val_a != val_b {
                    details.push(DivergenceDetail::CodeHashDiff {
                        account,
                        hash_a: val_a.cloned(),
                        hash_b: val_b.cloned(),
                    });
                }
            }
        }
        (Some(_), None) => {
            details.push(DivergenceDetail::KvDiff {
                key: "code_hashes".to_string(),
                value_a: Some("present".to_string()),
                value_b: None,
            });
        }
        (None, Some(_)) => {
            details.push(DivergenceDetail::KvDiff {
                key: "code_hashes".to_string(),
                value_a: None,
                value_b: Some("present".to_string()),
            });
        }
        (None, None) => {}
    }
}

fn compare_storage(a: &NodeSnapshot, b: &NodeSnapshot, details: &mut Vec<DivergenceDetail>) {
    match (&a.storage, &b.storage) {
        (Some(st_a), Some(st_b)) => {
            let all_keys: HashSet<(String, String)> =
                st_a.keys().chain(st_b.keys()).cloned().collect();
            for key in all_keys {
                let val_a = st_a.get(&key);
                let val_b = st_b.get(&key);
                if val_a != val_b {
                    let (account, slot) = key;
                    details.push(DivergenceDetail::StorageDiff {
                        account,
                        slot,
                        value_a: val_a.cloned(),
                        value_b: val_b.cloned(),
                    });
                }
            }
        }
        (Some(_), None) => {
            details.push(DivergenceDetail::KvDiff {
                key: "storage".to_string(),
                value_a: Some("present".to_string()),
                value_b: None,
            });
        }
        (None, Some(_)) => {
            details.push(DivergenceDetail::KvDiff {
                key: "storage".to_string(),
                value_a: None,
                value_b: Some("present".to_string()),
            });
        }
        (None, None) => {}
    }
}

fn compare_receipts(a: &NodeSnapshot, b: &NodeSnapshot, details: &mut Vec<DivergenceDetail>) {
    match (&a.receipts, &b.receipts) {
        (Some(rec_a), Some(rec_b)) => {
            let max_len = rec_a.len().max(rec_b.len());
            for i in 0..max_len {
                let r_a = rec_a.get(i);
                let r_b = rec_b.get(i);
                if r_a != r_b {
                    let idx = i;
                    let (a_str, b_str) = match (r_a, r_b) {
                        (Some(a), Some(b)) => (a.clone(), b.clone()),
                        (Some(a), None) => (a.clone(), "[missing]".into()),
                        (None, Some(b)) => ("[missing]".into(), b.clone()),
                        (None, None) => continue,
                    };
                    details.push(DivergenceDetail::ReceiptDiff {
                        index: idx,
                        receipt_a: a_str,
                        receipt_b: b_str,
                    });
                }
            }
        }
        (Some(_), None) => {
            details.push(DivergenceDetail::KvDiff {
                key: "receipts".to_string(),
                value_a: Some("present".to_string()),
                value_b: None,
            });
        }
        (None, Some(_)) => {
            details.push(DivergenceDetail::KvDiff {
                key: "receipts".to_string(),
                value_a: None,
                value_b: Some("present".to_string()),
            });
        }
        (None, None) => {}
    }
}

fn compare_logs(a: &NodeSnapshot, b: &NodeSnapshot, details: &mut Vec<DivergenceDetail>) {
    match (&a.logs, &b.logs) {
        (Some(log_a), Some(log_b)) => {
            let max_len = log_a.len().max(log_b.len());
            for i in 0..max_len {
                let l_a = log_a.get(i);
                let l_b = log_b.get(i);
                if l_a != l_b {
                    let idx = i;
                    let (a_str, b_str) = match (l_a, l_b) {
                        (Some(a), Some(b)) => (a.clone(), b.clone()),
                        (Some(a), None) => (a.clone(), "[missing]".into()),
                        (None, Some(b)) => ("[missing]".into(), b.clone()),
                        (None, None) => continue,
                    };
                    details.push(DivergenceDetail::LogDiff {
                        index: idx,
                        log_a: a_str,
                        log_b: b_str,
                    });
                }
            }
        }
        (Some(_), None) => {
            details.push(DivergenceDetail::KvDiff {
                key: "logs".to_string(),
                value_a: Some("present".to_string()),
                value_b: None,
            });
        }
        (None, Some(_)) => {
            details.push(DivergenceDetail::KvDiff {
                key: "logs".to_string(),
                value_a: None,
                value_b: Some("present".to_string()),
            });
        }
        (None, None) => {}
    }
}

// -----------------------------------------------------------------------------
// Internal comparison helpers
// -----------------------------------------------------------------------------

fn compare_btree_u64(
    a: &BTreeMap<String, u64>,
    b: &BTreeMap<String, u64>,
    node_a_id: &str,
    node_b_id: &str,
    details: &mut Vec<DivergenceDetail>,
    is_balance: bool,
) {
    let all_keys: HashSet<String> = a.keys().chain(b.keys()).cloned().collect();
    for key in all_keys {
        let val_a = a.get(&key);
        let val_b = b.get(&key);
        match (val_a, val_b) {
            (Some(&v_a), Some(&v_b)) if v_a != v_b => {
                if is_balance {
                    details.push(DivergenceDetail::BalanceDiff {
                        account: key.clone(),
                        value_a: v_a,
                        value_b: v_b,
                    });
                } else {
                    details.push(DivergenceDetail::NonceDiff {
                        account: key.clone(),
                        value_a: v_a,
                        value_b: v_b,
                    });
                }
            }
            (Some(_), None) => {
                details.push(DivergenceDetail::AccountMissing {
                    account: key.clone(),
                    present_in: node_a_id.to_string(),
                });
            }
            (None, Some(_)) => {
                details.push(DivergenceDetail::AccountMissing {
                    account: key.clone(),
                    present_in: node_b_id.to_string(),
                });
            }
            _ => {}
        }
    }
}

fn compare_btree_str(
    a: &BTreeMap<String, String>,
    b: &BTreeMap<String, String>,
    details: &mut Vec<DivergenceDetail>,
) {
    let all_keys: HashSet<String> = a.keys().chain(b.keys()).cloned().collect();
    for key in all_keys {
        let val_a = a.get(&key);
        let val_b = b.get(&key);
        if val_a != val_b {
            details.push(DivergenceDetail::KvDiff {
                key: key.clone(),
                value_a: val_a.cloned(),
                value_b: val_b.cloned(),
            });
        }
    }
}

// -----------------------------------------------------------------------------
// Multi‑node comparison
// -----------------------------------------------------------------------------

/// Compare multiple node snapshots at the same height.
///
/// Performs pairwise comparison of all `N*(N-1)/2` pairs.
/// If any pair has mismatched heights, an error is returned.
pub fn detect_divergence(snapshots: &[NodeSnapshot]) -> ReplayResult<DivergenceReport> {
    if snapshots.is_empty() {
        return Ok(DivergenceReport {
            divergences: vec![],
            all_agree: true,
            node_count: 0,
            heights_checked: vec![],
            report_time: None,
        });
    }

    let first_height = snapshots[0].height;
    for s in snapshots {
        if s.height != first_height {
            return Err(ReplayError::HeightMismatch(first_height, s.height));
        }
    }

    let mut divergences = Vec::new();
    for i in 0..snapshots.len() {
        for j in (i + 1)..snapshots.len() {
            if let Some(div) = compare_snapshots(&snapshots[i], &snapshots[j])? {
                divergences.push(div);
            }
        }
    }

    let all_agree = divergences.is_empty();
    Ok(DivergenceReport {
        divergences,
        all_agree,
        node_count: snapshots.len(),
        heights_checked: vec![first_height],
        report_time: None,
    })
}

/// Compare execution results across a range of heights.
///
/// `node_snapshots` is a map from `node_id` to a sorted list of snapshots.
/// The list for each node must be sorted by height (ascending).
/// Returns an error if any node is missing a snapshot at a height present in another node.
pub fn detect_divergence_range(
    node_snapshots: &BTreeMap<String, Vec<NodeSnapshot>>,
) -> ReplayResult<DivergenceReport> {
    let mut all_divergences = Vec::new();
    let mut heights_checked = Vec::new();

    let mut all_heights = std::collections::BTreeSet::new();
    for snapshots in node_snapshots.values() {
        for s in snapshots {
            all_heights.insert(s.height);
        }
    }

    for &height in &all_heights {
        heights_checked.push(height);

        let mut at_height = Vec::new();
        for (node_id, snapshots) in node_snapshots {
            match snapshots.iter().find(|s| s.height == height) {
                Some(snapshot) => at_height.push(snapshot),
                None => {
                    return Err(ReplayError::MissingSnapshot(node_id.clone(), height));
                }
            }
        }

        for i in 0..at_height.len() {
            for j in (i + 1)..at_height.len() {
                if let Some(div) = compare_snapshots(at_height[i], at_height[j])? {
                    all_divergences.push(div);
                }
            }
        }
    }

    let all_agree = all_divergences.is_empty();
    Ok(DivergenceReport {
        divergences: all_divergences,
        all_agree,
        node_count: node_snapshots.len(),
        heights_checked,
        report_time: None,
    })
}

// -----------------------------------------------------------------------------
// File I/O helpers
// -----------------------------------------------------------------------------

/// Save a snapshot to a file (JSON format).
pub fn save_snapshot_to_file(snapshot: &NodeSnapshot, path: &Path) -> ReplayResult<()> {
    let file = File::create(path).map_err(|e| ReplayError::Io(e.to_string()))?;
    let writer = BufWriter::new(file);
    serde_json::to_writer_pretty(writer, snapshot)
        .map_err(|e| ReplayError::Serialisation(e.to_string()))?;
    Ok(())
}

/// Load a snapshot from a JSON file.
pub fn load_snapshot_from_file(path: &Path) -> ReplayResult<NodeSnapshot> {
    let file = File::open(path).map_err(|e| ReplayError::Io(e.to_string()))?;
    let reader = BufReader::new(file);
    let snapshot: NodeSnapshot = serde_json::from_reader(reader)
        .map_err(|e| ReplayError::Serialisation(e.to_string()))?;
    Ok(snapshot)
}

/// Save a divergence report to a file (JSON format).
pub fn save_report_to_file(report: &DivergenceReport, path: &Path) -> ReplayResult<()> {
    let file = File::create(path).map_err(|e| ReplayError::Io(e.to_string()))?;
    let writer = BufWriter::new(file);
    serde_json::to_writer_pretty(writer, report)
        .map_err(|e| ReplayError::Serialisation(e.to_string()))?;
    Ok(())
}

/// Load a divergence report from a JSON file.
pub fn load_report_from_file(path: &Path) -> ReplayResult<DivergenceReport> {
    let file = File::open(path).map_err(|e| ReplayError::Io(e.to_string()))?;
    let reader = BufReader::new(file);
    let report: DivergenceReport = serde_json::from_reader(reader)
        .map_err(|e| ReplayError::Serialisation(e.to_string()))?;
    Ok(report)
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn snap(id: &str, height: Height, root: [u8; 32]) -> NodeSnapshot {
        NodeSnapshot {
            node_id: id.into(),
            height,
            state_root: Hash32(root),
            balances: None,
            nonces: None,
            kv: None,
            code_hashes: None,
            storage: None,
            receipts: None,
            logs: None,
            snapshot_time: None,
            node_version: None,
        }
    }

    fn snap_with_balances(
        id: &str,
        height: Height,
        root: [u8; 32],
        balances: BTreeMap<String, u64>,
    ) -> NodeSnapshot {
        NodeSnapshot {
            node_id: id.into(),
            height,
            state_root: Hash32(root),
            balances: Some(balances),
            nonces: None,
            kv: None,
            code_hashes: None,
            storage: None,
            receipts: None,
            logs: None,
            snapshot_time: None,
            node_version: None,
        }
    }

    #[test]
    fn test_no_divergence() -> ReplayResult<()> {
        let root = [1u8; 32];
        let snapshots = vec![
            snap("node-1", 100, root),
            snap("node-2", 100, root),
            snap("node-3", 100, root),
        ];

        let report = detect_divergence(&snapshots)?;
        assert!(report.all_agree);
        assert!(report.divergences.is_empty());
        Ok(())
    }

    #[test]
    fn test_divergence_detected() -> ReplayResult<()> {
        let snapshots = vec![
            snap("node-1", 100, [1u8; 32]),
            snap("node-2", 100, [2u8; 32]),
        ];

        let report = detect_divergence(&snapshots)?;
        assert!(!report.all_agree);
        assert_eq!(report.divergences.len(), 1);
        assert_eq!(report.divergences[0].height, 100);
        Ok(())
    }

    #[test]
    fn test_divergence_with_balance_details() -> ReplayResult<()> {
        let mut bal_a = BTreeMap::new();
        bal_a.insert("alice".into(), 1000u64);
        bal_a.insert("bob".into(), 500u64);

        let mut bal_b = BTreeMap::new();
        bal_b.insert("alice".into(), 999u64);
        bal_b.insert("bob".into(), 500u64);

        let snapshots = vec![
            snap_with_balances("node-1", 100, [1u8; 32], bal_a),
            snap_with_balances("node-2", 100, [2u8; 32], bal_b),
        ];

        let report = detect_divergence(&snapshots)?;
        assert!(!report.all_agree);
        let div = &report.divergences[0];
        assert!(div.details.iter().any(|d| matches!(d,
            DivergenceDetail::BalanceDiff { account, value_a: 1000, value_b: 999 }
            if account == "alice"
        )));
        Ok(())
    }

    #[test]
    fn test_divergence_missing_account() -> ReplayResult<()> {
        let mut bal_a = BTreeMap::new();
        bal_a.insert("alice".into(), 1000u64);
        bal_a.insert("charlie".into(), 100u64);

        let mut bal_b = BTreeMap::new();
        bal_b.insert("alice".into(), 1000u64);

        let snapshots = vec![
            snap_with_balances("node-1", 100, [1u8; 32], bal_a),
            snap_with_balances("node-2", 100, [2u8; 32], bal_b),
        ];

        let report = detect_divergence(&snapshots)?;
        assert!(!report.all_agree);
        let div = &report.divergences[0];
        assert!(div.details.iter().any(|d| matches!(d,
            DivergenceDetail::AccountMissing { account, present_in }
            if account == "charlie" && present_in == "node-1"
        )));
        Ok(())
    }

    #[test]
    fn test_height_mismatch_error() {
        let snapshots = vec![
            snap("node-1", 100, [1u8; 32]),
            snap("node-2", 101, [2u8; 32]),
        ];
        let result = detect_divergence(&snapshots);
        assert!(matches!(
            result,
            Err(ReplayError::HeightMismatch(100, 101))
        ));
    }

    #[test]
    fn test_three_node_partial_divergence() -> ReplayResult<()> {
        let snapshots = vec![
            snap("node-1", 100, [1u8; 32]),
            snap("node-2", 100, [1u8; 32]),
            snap("node-3", 100, [3u8; 32]),
        ];

        let report = detect_divergence(&snapshots)?;
        assert!(!report.all_agree);
        assert_eq!(report.divergences.len(), 2);
        Ok(())
    }

    #[test]
    fn test_range_detection() -> ReplayResult<()> {
        let mut node_snaps = BTreeMap::new();
        node_snaps.insert(
            "node-1".into(),
            vec![snap("node-1", 1, [1u8; 32]), snap("node-1", 2, [2u8; 32])],
        );
        node_snaps.insert(
            "node-2".into(),
            vec![
                snap("node-2", 1, [1u8; 32]),
                snap("node-2", 2, [9u8; 32]),
            ],
        );

        let report = detect_divergence_range(&node_snaps)?;
        assert!(!report.all_agree);
        assert_eq!(report.heights_checked.len(), 2);
        assert_eq!(report.divergences.len(), 1);
        assert_eq!(report.divergences[0].height, 2);
        Ok(())
    }

    #[test]
    fn test_range_missing_snapshot_error() {
        let mut node_snaps = BTreeMap::new();
        node_snaps.insert(
            "node-1".into(),
            vec![snap("node-1", 1, [1u8; 32]), snap("node-1", 2, [2u8; 32])],
        );
        node_snaps.insert("node-2".into(), vec![snap("node-2", 1, [1u8; 32])]);

        let result = detect_divergence_range(&node_snaps);
        assert!(matches!(
            result,
            Err(ReplayError::MissingSnapshot(node_id, height))
            if node_id == "node-2" && height == 2
        ));
    }

    #[test]
    fn test_kv_divergence() -> ReplayResult<()> {
        let mut kv_a = BTreeMap::new();
        kv_a.insert("key1".into(), "val_a".to_string());

        let mut kv_b = BTreeMap::new();
        kv_b.insert("key1".into(), "val_b".to_string());

        let a = NodeSnapshot {
            node_id: "node-1".into(),
            height: 10,
            state_root: Hash32([1u8; 32]),
            balances: None,
            nonces: None,
            kv: Some(kv_a),
            code_hashes: None,
            storage: None,
            receipts: None,
            logs: None,
            snapshot_time: None,
            node_version: None,
        };
        let b = NodeSnapshot {
            node_id: "node-2".into(),
            height: 10,
            state_root: Hash32([2u8; 32]),
            balances: None,
            nonces: None,
            kv: Some(kv_b),
            code_hashes: None,
            storage: None,
            receipts: None,
            logs: None,
            snapshot_time: None,
            node_version: None,
        };

        let div = compare_snapshots(&a, &b)?.expect("should have divergence");
        assert!(div.details.iter().any(|d| matches!(d,
            DivergenceDetail::KvDiff { key, .. } if key == "key1"
        )));
        Ok(())
    }

    #[test]
    fn test_divergence_detail_display() {
        let d = DivergenceDetail::BalanceDiff {
            account: "alice".into(),
            value_a: 100,
            value_b: 200,
        };
        let s = format!("{d}");
        assert!(s.contains("balance(alice)"));
        assert!(s.contains("100 vs 200"));
    }

    #[test]
    fn test_code_hash_divergence() -> ReplayResult<()> {
        let mut hash_a = BTreeMap::new();
        hash_a.insert("0x123".into(), Hash32([1u8; 32]));

        let mut hash_b = BTreeMap::new();
        hash_b.insert("0x123".into(), Hash32([2u8; 32]));

        let a = NodeSnapshot {
            node_id: "node-1".into(),
            height: 10,
            state_root: Hash32([1u8; 32]),
            balances: None,
            nonces: None,
            kv: None,
            code_hashes: Some(hash_a),
            storage: None,
            receipts: None,
            logs: None,
            snapshot_time: None,
            node_version: None,
        };
        let b = NodeSnapshot {
            node_id: "node-2".into(),
            height: 10,
            state_root: Hash32([2u8; 32]),
            balances: None,
            nonces: None,
            kv: None,
            code_hashes: Some(hash_b),
            storage: None,
            receipts: None,
            logs: None,
            snapshot_time: None,
            node_version: None,
        };

        let div = compare_snapshots(&a, &b)?.expect("should have divergence");
        assert!(div.details.iter().any(|d| matches!(d,
            DivergenceDetail::CodeHashDiff { account, .. }
            if account == "0x123"
        )));
        Ok(())
    }
}
