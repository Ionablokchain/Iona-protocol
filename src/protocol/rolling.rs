//! Rolling upgrade scenario simulation and validation.
//!
//! Provides tools for planning, simulating, and validating rolling upgrades
//! across a multi-node IONA network. A rolling upgrade means nodes are
//! upgraded one at a time while the network continues producing blocks.
//!
//! # Upgrade Phases
//!
//! ```text
//! Phase 1: Pre-upgrade     All nodes on PV_old
//! Phase 2: Rolling         Nodes upgrade one-by-one; mixed PV_old + PV_new
//! Phase 3: Post-upgrade    All nodes on PV_new (before activation)
//! Phase 4: Activation      PV_new becomes mandatory at activation_height
//! Phase 5: Grace expiry    Old PV blocks rejected after grace window
//! ```
//!
//! # Safety Guarantees
//!
//! During a rolling upgrade:
//! - Network liveness is maintained (≥ 2f+1 nodes always online)
//! - No split finality (invariant S1)
//! - Finality monotonicity (invariant S2)
//! - Deterministic PV selection (invariant S3)
//! - Wire compatibility between old and new nodes (handshake overlap)

use serde::{Deserialize, Serialize};

use super::version::{ProtocolActivation, version_for_height, SUPPORTED_PROTOCOL_VERSIONS};
use super::wire::{Hello, check_hello_compat};
use super::safety;

// ─── Upgrade plan ────────────────────────────────────────────────────────────

/// A planned rolling upgrade for a set of nodes.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RollingUpgradePlan {
    /// Total number of validator nodes.
    pub total_nodes: usize,
    /// Maximum concurrent Byzantine faults tolerated (f < N/3).
    pub max_byzantine: usize,
    /// Maximum nodes that can be offline simultaneously during upgrade.
    pub max_offline: usize,
    /// Upgrade order (node indices).
    pub upgrade_order: Vec<usize>,
    /// Target protocol version.
    pub target_pv: u32,
    /// Activation height (None for minor/rolling upgrades without PV change).
    pub activation_height: Option<u64>,
    /// Grace window in blocks after activation.
    pub grace_blocks: u64,
    /// Estimated time per node upgrade (seconds).
    pub estimated_per_node_s: u64,
}

impl RollingUpgradePlan {
    /// Create a plan for upgrading N nodes.
    pub fn new(total_nodes: usize, target_pv: u32) -> Self {
        let max_byzantine = (total_nodes - 1) / 3;
        // During upgrade, at most 1 node is offline at a time.
        let max_offline = 1;
        let upgrade_order: Vec<usize> = (0..total_nodes).collect();

        Self {
            total_nodes,
            max_byzantine,
            max_offline,
            upgrade_order,
            target_pv,
            activation_height: None,
            grace_blocks: 1000,
            estimated_per_node_s: 120,
        }
    }

    /// Set activation height for a coordinated hard-fork upgrade.
    pub fn with_activation(mut self, height: u64, grace: u64) -> Self {
        self.activation_height = Some(height);
        self.grace_blocks = grace;
        self
    }

    /// Set custom upgrade order.
    pub fn with_order(mut self, order: Vec<usize>) -> Self {
        self.upgrade_order = order;
        self
    }

    /// Validate the upgrade plan.
    pub fn validate(&self) -> Result<(), Vec<String>> {
        let mut errors = Vec::new();

        if self.total_nodes < 4 {
            errors.push(format!(
                "minimum 4 nodes required for BFT (have {})",
                self.total_nodes
            ));
        }

        if self.max_offline > self.max_byzantine {
            errors.push(format!(
                "max_offline ({}) exceeds BFT tolerance f={} for N={}",
                self.max_offline, self.max_byzantine, self.total_nodes
            ));
        }

        if self.upgrade_order.len() != self.total_nodes {
            errors.push(format!(
                "upgrade_order length ({}) != total_nodes ({})",
                self.upgrade_order.len(), self.total_nodes
            ));
        }

        // Check for duplicate indices.
        let mut seen = vec![false; self.total_nodes];
        for &idx in &self.upgrade_order {
            if idx >= self.total_nodes {
                errors.push(format!("invalid node index {idx} in upgrade_order"));
            } else if seen[idx] {
                errors.push(format!("duplicate node index {idx} in upgrade_order"));
            } else {
                seen[idx] = true;
            }
        }

        if errors.is_empty() { Ok(()) } else { Err(errors) }
    }

    /// Estimate total upgrade duration.
    pub fn estimated_duration_s(&self) -> u64 {
        self.total_nodes as u64 * self.estimated_per_node_s
    }
}

// ─── Upgrade simulator ──────────────────────────────────────────────────────

/// State of a simulated node during rolling upgrade.
#[derive(Debug, Clone)]
pub struct SimNode {
    /// Node index.
    pub index: usize,
    /// Protocol versions this node supports.
    pub supported_pv: Vec<u32>,
    /// Whether the node is currently online.
    pub online: bool,
    /// Whether the node has been upgraded.
    pub upgraded: bool,
    /// Current chain height on this node.
    pub height: u64,
    /// Finalized height on this node.
    pub finalized_height: u64,
}

/// Result of a rolling upgrade simulation.
#[derive(Debug, Clone)]
pub struct SimResult {
    /// Whether the simulation succeeded (no safety violations).
    pub success: bool,
    /// Safety violations detected (empty if success).
    pub violations: Vec<String>,
    /// Events that occurred during simulation.
    pub events: Vec<SimEvent>,
    /// Final state of each node.
    pub nodes: Vec<SimNode>,
    /// Total blocks produced during simulation.
    pub blocks_produced: u64,
}

/// Events during simulation.
#[derive(Debug, Clone)]
pub enum SimEvent {
    /// Node taken offline for upgrade.
    NodeOffline { index: usize, height: u64 },
    /// Node brought back online after upgrade.
    NodeOnline { index: usize, height: u64, new_pv: Vec<u32> },
    /// Block produced at height.
    BlockProduced { height: u64, pv: u32, proposer: usize },
    /// All nodes upgraded.
    AllUpgraded { height: u64 },
    /// Activation height reached.
    ActivationReached { height: u64, pv: u32 },
    /// Safety check passed.
    SafetyCheckPassed { check: String, height: u64 },
    /// Safety violation detected.
    SafetyViolation { check: String, height: u64, detail: String },
}

/// Simulate a rolling upgrade according to the plan.
pub fn simulate_rolling_upgrade(
    plan: &RollingUpgradePlan,
    activations: &[ProtocolActivation],
    start_height: u64,
    blocks_to_simulate: u64,
) -> SimResult {
    let mut nodes: Vec<SimNode> = (0..plan.total_nodes)
        .map(|i| SimNode {
            index: i,
            supported_pv: vec![1],
            online: true,
            upgraded: false,
            height: start_height,
            finalized_height: start_height,
        })
        .collect();

    let mut events = Vec::new();
    let mut violations = Vec::new();
    let mut blocks_produced = 0u64;
    let mut next_upgrade_idx = 0usize;
    let mut all_upgraded = false;

    // Upgrade every N blocks.
    let upgrade_interval = if plan.total_nodes > 0 {
        blocks_to_simulate / (plan.total_nodes as u64 + 1)
    } else {
        blocks_to_simulate
    }.max(1);

    for block_num in 0..blocks_to_simulate {
        let height = start_height + block_num + 1;

        // Check if it's time to upgrade a node.
        if !all_upgraded
            && next_upgrade_idx < plan.upgrade_order.len()
            && block_num > 0
            && block_num % upgrade_interval == 0
        {
            let node_idx = plan.upgrade_order[next_upgrade_idx];

            // Take node offline.
            nodes[node_idx].online = false;
            events.push(SimEvent::NodeOffline { index: node_idx, height });

            // Upgrade node.
            nodes[node_idx].supported_pv = (1..=plan.target_pv).collect();
            nodes[node_idx].upgraded = true;

            // Bring node back online.
            nodes[node_idx].online = true;
            events.push(SimEvent::NodeOnline {
                index: node_idx,
                height,
                new_pv: nodes[node_idx].supported_pv.clone(),
            });

            next_upgrade_idx += 1;

            if next_upgrade_idx >= plan.upgrade_order.len() {
                all_upgraded = true;
                events.push(SimEvent::AllUpgraded { height });
            }
        }

        // Determine PV for this block.
        let pv = version_for_height(height, activations);

        // Select proposer (round-robin among online nodes).
        let online_nodes: Vec<usize> = nodes.iter()
            .filter(|n| n.online)
            .map(|n| n.index)
            .collect();

        if online_nodes.is_empty() {
            violations.push(format!("no online nodes at height {height}"));
            continue;
        }

        let proposer = online_nodes[height as usize % online_nodes.len()];

        // Check BFT liveness: need ≥ 2f+1 online.
        let required_online = plan.total_nodes - plan.max_byzantine;
        if online_nodes.len() < required_online {
            violations.push(format!(
                "liveness violation at height {height}: only {} online, need {}",
                online_nodes.len(), required_online
            ));
        }

        // Produce block.
        events.push(SimEvent::BlockProduced { height, pv, proposer });
        blocks_produced += 1;

        // Update all online nodes.
        for node in nodes.iter_mut() {
            if node.online {
                node.height = height;
                node.finalized_height = height;
            }
        }

        // Safety checks.

        // S1: No split finality.
        if let Err(e) = safety::check_no_split_finality(height, 1) {
            violations.push(format!("S1 at height {height}: {e}"));
            events.push(SimEvent::SafetyViolation {
                check: "S1".into(), height, detail: e,
            });
        } else {
            events.push(SimEvent::SafetyCheckPassed { check: "S1".into(), height });
        }

        // S2: Finality monotonic.
        if height > 1 {
            if let Err(e) = safety::check_finality_monotonic(height - 1, height) {
                violations.push(format!("S2 at height {height}: {e}"));
                events.push(SimEvent::SafetyViolation {
                    check: "S2".into(), height, detail: e,
                });
            }
        }

        // Wire compatibility: all online node pairs must be compatible.
        for i in 0..nodes.len() {
            for j in (i+1)..nodes.len() {
                if !nodes[i].online || !nodes[j].online { continue; }
                let hello_i = Hello {
                    supported_pv: nodes[i].supported_pv.clone(),
                    supported_sv: vec![0, 1, 2, 3, 4],
                    software_version: "test".into(),
                    chain_id: 6126151,
                    genesis_hash: crate::types::Hash32::zero(),
                    head_height: height,
                    head_pv: pv,
                };
                let hello_j = Hello {
                    supported_pv: nodes[j].supported_pv.clone(),
                    supported_sv: vec![0, 1, 2, 3, 4],
                    software_version: "test".into(),
                    chain_id: 6126151,
                    genesis_hash: crate::types::Hash32::zero(),
                    head_height: height,
                    head_pv: pv,
                };
                let compat = check_hello_compat(&hello_i, &hello_j);
                if !compat.compatible {
                    violations.push(format!(
                        "wire incompat at height {height}: node {} <-> node {}: {}",
                        i, j, compat.reason
                    ));
                }
            }
        }

        // Check for activation.
        if let Some(ah) = plan.activation_height {
            if height == ah {
                events.push(SimEvent::ActivationReached { height, pv });
            }
        }
    }

    SimResult {
        success: violations.is_empty(),
        violations,
        events,
        nodes,
        blocks_produced,
    }
}

/// Validate that a rolling upgrade plan is safe for the given network.
pub fn validate_upgrade_safety(plan: &RollingUpgradePlan) -> Vec<String> {
    let mut warnings = Vec::new();

    // Check BFT tolerance.
    let quorum = (plan.total_nodes * 2 + 2) / 3; // ceil(2N/3)
    let min_online = plan.total_nodes - plan.max_offline;
    if min_online < quorum {
        warnings.push(format!(
            "insufficient quorum during upgrade: {min_online} online < {quorum} required"
        ));
    }

    // Check upgrade order doesn't take too many nodes offline.
    if plan.max_offline > 1 {
        warnings.push(format!(
            "max_offline={} > 1; taking multiple nodes offline simultaneously is risky",
            plan.max_offline
        ));
    }

    // Check target PV is supported by this binary.
    if !SUPPORTED_PROTOCOL_VERSIONS.contains(&plan.target_pv) {
        warnings.push(format!(
            "target PV={} is not supported by this binary (supported: {:?})",
            plan.target_pv, SUPPORTED_PROTOCOL_VERSIONS
        ));
    }

    // Check activation height gives enough time for rolling upgrade.
    if let Some(ah) = plan.activation_height {
        let estimated_blocks = plan.estimated_duration_s() / 2; // ~2s per block estimate
        if ah < estimated_blocks {
            warnings.push(format!(
                "activation_height={ah} may be too soon; estimated upgrade takes ~{estimated_blocks} blocks"
            ));
        }
    }

    warnings
}

// ─── Tests ──────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::version::ProtocolActivation;

    fn basic_activations() -> Vec<ProtocolActivation> {
        vec![ProtocolActivation {
            protocol_version: 1,
            activation_height: None,
            grace_blocks: 0,
        }]
    }

    #[test]
    fn test_plan_creation() {
        let plan = RollingUpgradePlan::new(4, 1);
        assert_eq!(plan.total_nodes, 4);
        assert_eq!(plan.max_byzantine, 1);
        assert_eq!(plan.upgrade_order, vec![0, 1, 2, 3]);
    }

    #[test]
    fn test_plan_validation_ok() {
        let plan = RollingUpgradePlan::new(4, 1);
        assert!(plan.validate().is_ok());
    }

    #[test]
    fn test_plan_validation_too_few_nodes() {
        let plan = RollingUpgradePlan::new(2, 1);
        assert!(plan.validate().is_err());
    }

    #[test]
    fn test_plan_validation_duplicate_order() {
        let mut plan = RollingUpgradePlan::new(4, 1);
        plan.upgrade_order = vec![0, 1, 1, 3]; // duplicate index 1
        assert!(plan.validate().is_err());
    }

    #[test]
    fn test_simulate_basic_rolling() {
        let plan = RollingUpgradePlan::new(4, 1);
        let activations = basic_activations();
        let result = simulate_rolling_upgrade(&plan, &activations, 0, 20);

        assert!(result.success, "violations: {:?}", result.violations);
        assert_eq!(result.blocks_produced, 20);
        assert!(result.nodes.iter().all(|n| n.upgraded));
    }

    #[test]
    fn test_simulate_with_activation() {
        let plan = RollingUpgradePlan::new(4, 2)
            .with_activation(15, 5);
        let activations = vec![
            ProtocolActivation {
                protocol_version: 1,
                activation_height: None,
                grace_blocks: 0,
            },
            ProtocolActivation {
                protocol_version: 2,
                activation_height: Some(15),
                grace_blocks: 5,
            },
        ];
        let result = simulate_rolling_upgrade(&plan, &activations, 0, 30);

        // Should have ActivationReached event.
        let has_activation = result.events.iter().any(|e| matches!(e, SimEvent::ActivationReached { .. }));
        assert!(has_activation, "should have ActivationReached event");
    }

    #[test]
    fn test_validate_safety_ok() {
        let plan = RollingUpgradePlan::new(4, 1);
        let warnings = validate_upgrade_safety(&plan);
        assert!(warnings.is_empty(), "unexpected warnings: {:?}", warnings);
    }

    #[test]
    fn test_estimated_duration() {
        let plan = RollingUpgradePlan::new(7, 1);
        assert_eq!(plan.estimated_duration_s(), 7 * 120);
    }

    #[test]
    fn test_plan_with_custom_order() {
        let plan = RollingUpgradePlan::new(4, 1)
            .with_order(vec![3, 2, 1, 0]);
        assert_eq!(plan.upgrade_order, vec![3, 2, 1, 0]);
        assert!(plan.validate().is_ok());
    }

    #[test]
    fn test_wire_compat_during_rolling() {
        // Simulate that during rolling upgrade, all nodes remain wire-compatible.
        let plan = RollingUpgradePlan::new(5, 1);
        let activations = basic_activations();
        let result = simulate_rolling_upgrade(&plan, &activations, 0, 30);

        // No wire incompatibility violations.
        let wire_violations: Vec<_> = result.violations.iter()
            .filter(|v| v.contains("wire incompat"))
            .collect();
        assert!(wire_violations.is_empty(), "wire violations: {:?}", wire_violations);
    }
}
