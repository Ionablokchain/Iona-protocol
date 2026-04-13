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

use crate::types::{Hash32, Height};
use std::collections::BTreeMap;

/// A snapshot of a node's state at a given height.
#[derive(Debug, Clone)]
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
}

/// A detected divergence between two nodes.
#[derive(Debug, Clone)]
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

/// A specific difference between two node states.
#[derive(Debug, Clone)]
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
    AccountMissing { account: String, present_in: String },
}

impl std::fmt::Display for DivergenceDetail {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
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
        }
    }
}

/// Result of comparing two or more node snapshots.
#[derive(Debug, Clone)]
pub struct DivergenceReport {
    /// All detected divergences.
    pub divergences: Vec<Divergence>,
    /// Whether all nodes agree.
    pub all_agree: bool,
    /// Number of nodes compared.
    pub node_count: usize,
    /// Heights checked.
    pub heights_checked: Vec<Height>,
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

// ─── Comparison functions ───────────────────────────────────────────────────

/// Compare two node snapshots at the same height.
pub fn compare_snapshots(a: &NodeSnapshot, b: &NodeSnapshot) -> Option<Divergence> {
    if a.height != b.height {
        return None; // Cannot compare different heights.
    }

    if a.state_root == b.state_root {
        return None; // No divergence.
    }

    let mut details = Vec::new();

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

/// Compare multiple node snapshots at the same height.
///
/// Performs pairwise comparison of all N*(N-1)/2 pairs.
pub fn detect_divergence(snapshots: &[NodeSnapshot]) -> DivergenceReport {
    let heights: Vec<Height> = snapshots.iter().map(|s| s.height).collect();
    let mut divergences = Vec::new();

    for i in 0..snapshots.len() {
        for j in (i + 1)..snapshots.len() {
            if let Some(div) = compare_snapshots(&snapshots[i], &snapshots[j]) {
                divergences.push(div);
            }
        }
    }

    let all_agree = divergences.is_empty();
    DivergenceReport {
        divergences,
        all_agree,
        node_count: snapshots.len(),
        heights_checked: heights,
    }
}

/// Compare execution results across a range of heights.
///
/// `node_snapshots` is a map from node_id to a sorted list of snapshots.
pub fn detect_divergence_range(
    node_snapshots: &BTreeMap<String, Vec<NodeSnapshot>>,
) -> DivergenceReport {
    let mut all_divergences = Vec::new();
    let mut heights_checked = Vec::new();

    // Collect all unique heights.
    let mut all_heights = std::collections::BTreeSet::new();
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

        for i in 0..at_height.len() {
            for j in (i + 1)..at_height.len() {
                if let Some(div) = compare_snapshots(at_height[i], at_height[j]) {
                    all_divergences.push(div);
                }
            }
        }
    }

    let all_agree = all_divergences.is_empty();
    DivergenceReport {
        divergences: all_divergences,
        all_agree,
        node_count: node_snapshots.len(),
        heights_checked,
    }
}

// ─── Tests ──────────────────────────────────────────────────────────────────

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
        }
    }

    #[test]
    fn test_no_divergence() {
        let root = [1u8; 32];
        let snapshots = vec![
            snap("node-1", 100, root),
            snap("node-2", 100, root),
            snap("node-3", 100, root),
        ];

        let report = detect_divergence(&snapshots);
        assert!(report.all_agree, "report: {report}");
        assert!(report.divergences.is_empty());
    }

    #[test]
    fn test_divergence_detected() {
        let snapshots = vec![
            snap("node-1", 100, [1u8; 32]),
            snap("node-2", 100, [2u8; 32]),
        ];

        let report = detect_divergence(&snapshots);
        assert!(!report.all_agree);
        assert_eq!(report.divergences.len(), 1);
        assert_eq!(report.divergences[0].height, 100);
    }

    #[test]
    fn test_divergence_with_balance_details() {
        let mut bal_a = BTreeMap::new();
        bal_a.insert("alice".into(), 1000u64);
        bal_a.insert("bob".into(), 500u64);

        let mut bal_b = BTreeMap::new();
        bal_b.insert("alice".into(), 999u64); // Different!
        bal_b.insert("bob".into(), 500u64);

        let snapshots = vec![
            snap_with_balances("node-1", 100, [1u8; 32], bal_a),
            snap_with_balances("node-2", 100, [2u8; 32], bal_b),
        ];

        let report = detect_divergence(&snapshots);
        assert!(!report.all_agree);
        let div = &report.divergences[0];
        assert!(div.details.iter().any(|d| matches!(d,
            DivergenceDetail::BalanceDiff { account, value_a: 1000, value_b: 999 }
            if account == "alice"
        )));
    }

    #[test]
    fn test_divergence_missing_account() {
        let mut bal_a = BTreeMap::new();
        bal_a.insert("alice".into(), 1000u64);
        bal_a.insert("charlie".into(), 100u64);

        let mut bal_b = BTreeMap::new();
        bal_b.insert("alice".into(), 1000u64);
        // charlie missing from node-2

        let snapshots = vec![
            snap_with_balances("node-1", 100, [1u8; 32], bal_a),
            snap_with_balances("node-2", 100, [2u8; 32], bal_b),
        ];

        let report = detect_divergence(&snapshots);
        assert!(!report.all_agree);
        let div = &report.divergences[0];
        assert!(div.details.iter().any(|d| matches!(d,
            DivergenceDetail::AccountMissing { account, present_in }
            if account == "charlie" && present_in == "node-1"
        )));
    }

    #[test]
    fn test_three_node_partial_divergence() {
        let snapshots = vec![
            snap("node-1", 100, [1u8; 32]),
            snap("node-2", 100, [1u8; 32]),
            snap("node-3", 100, [3u8; 32]), // node-3 diverged
        ];

        let report = detect_divergence(&snapshots);
        assert!(!report.all_agree);
        // node-3 diverges from both node-1 and node-2.
        assert_eq!(report.divergences.len(), 2);
    }

    #[test]
    fn test_range_detection() {
        let mut node_snaps = BTreeMap::new();
        node_snaps.insert(
            "node-1".into(),
            vec![snap("node-1", 1, [1u8; 32]), snap("node-1", 2, [2u8; 32])],
        );
        node_snaps.insert(
            "node-2".into(),
            vec![
                snap("node-2", 1, [1u8; 32]),
                snap("node-2", 2, [9u8; 32]), // divergence at height 2
            ],
        );

        let report = detect_divergence_range(&node_snaps);
        assert!(!report.all_agree);
        assert_eq!(report.heights_checked.len(), 2);
        assert_eq!(report.divergences.len(), 1);
        assert_eq!(report.divergences[0].height, 2);
    }

    #[test]
    fn test_report_display() {
        let snapshots = vec![
            snap("node-1", 100, [1u8; 32]),
            snap("node-2", 100, [2u8; 32]),
        ];
        let report = detect_divergence(&snapshots);
        let s = format!("{report}");
        assert!(s.contains("DIVERGENCE DETECTED"));
    }

    #[test]
    fn test_kv_divergence() {
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
        };
        let b = NodeSnapshot {
            node_id: "node-2".into(),
            height: 10,
            state_root: Hash32([2u8; 32]),
            balances: None,
            nonces: None,
            kv: Some(kv_b),
        };

        let div = compare_snapshots(&a, &b).unwrap();
        assert!(div.details.iter().any(|d| matches!(d,
            DivergenceDetail::KvDiff { key, .. } if key == "key1"
        )));
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
    }
}
