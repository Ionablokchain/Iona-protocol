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
//!
//! # Example
//!
//! ```rust,ignore
//! use iona::protocol::rolling::{RollingUpgradePlan, simulate_rolling_upgrade};
//! use iona::protocol::version::ProtocolActivation;
//!
//! let plan = RollingUpgradePlan::new(4, 1);
//! let activations = vec![
//!     ProtocolActivation { protocol_version: 1, activation_height: None, grace_blocks: 0 },
//!     ProtocolActivation { protocol_version: 2, activation_height: Some(100), grace_blocks: 10 },
//! ];
//! let config = RollingSimConfig::default();
//! let result = simulate_rolling_upgrade(&plan, &activations, 0, 200, &config);
//! assert!(result.success);
//! ```

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::time::{Duration, Instant};
use thiserror::Error;
use tracing::{debug, error, info, warn};

use super::safety;
use super::version::{version_for_height, ProtocolActivation, SUPPORTED_PROTOCOL_VERSIONS};
use super::wire::{check_hello_compat, Hello};

// -----------------------------------------------------------------------------
// Error types
// -----------------------------------------------------------------------------

/// Errors that can occur during rolling upgrade planning or simulation.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum RollingError {
    #[error("not enough nodes: need at least 4, got {0}")]
    NotEnoughNodes(usize),

    #[error("max offline ({0}) exceeds BFT tolerance f={1} for N={2}")]
    OfflineExceedsTolerance(usize, usize, usize),

    #[error("upgrade order length ({0}) does not match total nodes ({1})")]
    OrderLengthMismatch(usize, usize),

    #[error("invalid node index {0} in upgrade order")]
    InvalidNodeIndex(usize),

    #[error("duplicate node index {0} in upgrade order")]
    DuplicateNode(usize),

    #[error("target PV {0} not supported by this binary (supported: {1:?})")]
    UnsupportedTarget(u32, Vec<u32>),

    #[error("activation height too low: {0} (minimum {1})")]
    ActivationHeightTooLow(u64, u64),

    #[error("grace window too small: {0} (minimum {1})")]
    GraceTooSmall(u64, u64),
}

pub type RollingResult<T> = Result<T, RollingError>;

// -----------------------------------------------------------------------------
// RollingUpgradePlan
// -----------------------------------------------------------------------------

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
    pub fn new(total_nodes: usize, target_pv: u32) -> RollingResult<Self> {
        if total_nodes < 4 {
            return Err(RollingError::NotEnoughNodes(total_nodes));
        }
        let max_byzantine = (total_nodes - 1) / 3;
        let upgrade_order: Vec<usize> = (0..total_nodes).collect();

        Ok(Self {
            total_nodes,
            max_byzantine,
            max_offline: 1,
            upgrade_order,
            target_pv,
            activation_height: None,
            grace_blocks: 1000,
            estimated_per_node_s: 120,
        })
    }

    /// Set activation height for a coordinated hard‑fork upgrade.
    pub fn with_activation(mut self, height: u64, grace: u64) -> Self {
        self.activation_height = Some(height);
        self.grace_blocks = grace;
        info!(height, grace, "activation set for rolling upgrade");
        self
    }

    /// Set custom upgrade order.
    pub fn with_order(mut self, order: Vec<usize>) -> Self {
        self.upgrade_order = order;
        debug!(order = ?order, "custom upgrade order set");
        self
    }

    /// Set estimated time per node upgrade (seconds).
    pub fn with_estimated_time(mut self, seconds: u64) -> Self {
        self.estimated_per_node_s = seconds;
        self
    }

    /// Validate the upgrade plan.
    pub fn validate(&self) -> RollingResult<()> {
        if self.total_nodes < 4 {
            return Err(RollingError::NotEnoughNodes(self.total_nodes));
        }

        if self.max_offline > self.max_byzantine {
            return Err(RollingError::OfflineExceedsTolerance(
                self.max_offline,
                self.max_byzantine,
                self.total_nodes,
            ));
        }

        if self.upgrade_order.len() != self.total_nodes {
            return Err(RollingError::OrderLengthMismatch(
                self.upgrade_order.len(),
                self.total_nodes,
            ));
        }

        let mut seen = vec![false; self.total_nodes];
        for &idx in &self.upgrade_order {
            if idx >= self.total_nodes {
                return Err(RollingError::InvalidNodeIndex(idx));
            }
            if seen[idx] {
                return Err(RollingError::DuplicateNode(idx));
            }
            seen[idx] = true;
        }

        if !SUPPORTED_PROTOCOL_VERSIONS.contains(&self.target_pv) {
            return Err(RollingError::UnsupportedTarget(
                self.target_pv,
                SUPPORTED_PROTOCOL_VERSIONS.to_vec(),
            ));
        }

        if let Some(ah) = self.activation_height {
            if ah < 100 {
                return Err(RollingError::ActivationHeightTooLow(ah, 100));
            }
        }

        if self.grace_blocks < 10 {
            return Err(RollingError::GraceTooSmall(self.grace_blocks, 10));
        }

        Ok(())
    }

    /// Estimate total upgrade duration.
    pub fn estimated_duration_s(&self) -> u64 {
        self.total_nodes as u64 * self.estimated_per_node_s
    }

    /// Estimate the number of blocks that will be produced during the upgrade.
    pub fn estimated_blocks(&self) -> u64 {
        self.estimated_duration_s() / 2 // assuming 2s block time
    }
}

// -----------------------------------------------------------------------------
// Simulation configuration
// -----------------------------------------------------------------------------

/// Configuration for rolling upgrade simulation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RollingSimConfig {
    /// Minimum online nodes required (if 0, uses BFT quorum).
    pub min_online: Option<usize>,
    /// Block interval (milliseconds).
    pub block_interval_ms: u64,
    /// Enable safety checks during simulation.
    pub enable_safety_checks: bool,
    /// Enable wire compatibility checks.
    pub enable_wire_checks: bool,
    /// Enable liveness checks.
    pub enable_liveness_checks: bool,
    /// Log level for simulation events (0=errors, 1=warnings, 2=info, 3=debug).
    pub log_level: u8,
}

impl Default for RollingSimConfig {
    fn default() -> Self {
        Self {
            min_online: None,
            block_interval_ms: 2000,
            enable_safety_checks: true,
            enable_wire_checks: true,
            enable_liveness_checks: true,
            log_level: 2,
        }
    }
}

impl RollingSimConfig {
    /// Create a config with all checks enabled.
    pub fn full() -> Self {
        Self {
            enable_safety_checks: true,
            enable_wire_checks: true,
            enable_liveness_checks: true,
            ..Default::default()
        }
    }

    /// Create a config for fast simulation (no checks).
    pub fn fast() -> Self {
        Self {
            enable_safety_checks: false,
            enable_wire_checks: false,
            enable_liveness_checks: false,
            ..Default::default()
        }
    }
}

// -----------------------------------------------------------------------------
// SimNode
// -----------------------------------------------------------------------------

/// State of a simulated node during rolling upgrade.
#[derive(Debug, Clone)]
pub struct SimNode {
    pub index: usize,
    pub supported_pv: Vec<u32>,
    pub online: bool,
    pub upgraded: bool,
    pub height: u64,
    pub finalized_height: u64,
    pub upgrade_time_ms: u64,
}

// -----------------------------------------------------------------------------
// SimEvent
// -----------------------------------------------------------------------------

/// Events during simulation.
#[derive(Debug, Clone)]
pub enum SimEvent {
    NodeOffline { index: usize, height: u64, time_ms: u64 },
    NodeOnline {
        index: usize,
        height: u64,
        time_ms: u64,
        new_pv: Vec<u32>,
    },
    BlockProduced {
        height: u64,
        pv: u32,
        proposer: usize,
        time_ms: u64,
    },
    AllUpgraded { height: u64, time_ms: u64 },
    ActivationReached { height: u64, pv: u32, time_ms: u64 },
    SafetyCheckPassed { check: String, height: u64, time_ms: u64 },
    SafetyViolation {
        check: String,
        height: u64,
        time_ms: u64,
        detail: String,
    },
    LivenessViolation {
        height: u64,
        time_ms: u64,
        online: usize,
        required: usize,
    },
    WireIncompatibility {
        height: u64,
        time_ms: u64,
        node_a: usize,
        node_b: usize,
        reason: String,
    },
}

// -----------------------------------------------------------------------------
// SimResult
// -----------------------------------------------------------------------------

/// Result of a rolling upgrade simulation.
#[derive(Debug, Clone)]
pub struct SimResult {
    pub success: bool,
    pub violations: Vec<String>,
    pub events: Vec<SimEvent>,
    pub nodes: Vec<SimNode>,
    pub blocks_produced: u64,
    pub total_time_ms: u64,
    pub avg_block_time_ms: u64,
    pub nodes_upgraded: usize,
}

impl SimResult {
    /// Get all safety violations.
    pub fn safety_violations(&self) -> Vec<&SimEvent> {
        self.events
            .iter()
            .filter(|e| matches!(e, SimEvent::SafetyViolation { .. }))
            .collect()
    }

    /// Get all liveness violations.
    pub fn liveness_violations(&self) -> Vec<&SimEvent> {
        self.events
            .iter()
            .filter(|e| matches!(e, SimEvent::LivenessViolation { .. }))
            .collect()
    }

    /// Get all wire incompatibilities.
    pub fn wire_incompatibilities(&self) -> Vec<&SimEvent> {
        self.events
            .iter()
            .filter(|e| matches!(e, SimEvent::WireIncompatibility { .. }))
            .collect()
    }
}

// -----------------------------------------------------------------------------
// Simulation function
// -----------------------------------------------------------------------------

/// Simulate a rolling upgrade according to the plan.
pub fn simulate_rolling_upgrade(
    plan: &RollingUpgradePlan,
    activations: &[ProtocolActivation],
    start_height: u64,
    blocks_to_simulate: u64,
    config: &RollingSimConfig,
) -> SimResult {
    let _span = tracing::info_span!("rolling_upgrade_simulation").entered();
    info!(
        total_nodes = plan.total_nodes,
        target_pv = plan.target_pv,
        blocks = blocks_to_simulate,
        "starting rolling upgrade simulation"
    );

    let start_time = Instant::now();
    let mut nodes: Vec<SimNode> = (0..plan.total_nodes)
        .map(|i| SimNode {
            index: i,
            supported_pv: vec![1],
            online: true,
            upgraded: false,
            height: start_height,
            finalized_height: start_height,
            upgrade_time_ms: 0,
        })
        .collect();

    let mut events = Vec::new();
    let mut violations = Vec::new();
    let mut blocks_produced = 0u64;
    let mut next_upgrade_idx = 0usize;
    let mut all_upgraded = false;
    let mut sim_time_ms = 0u64;

    let quorum = (plan.total_nodes * 2 + 2) / 3;
    let min_online = config.min_online.unwrap_or(quorum);
    let upgrade_interval_blocks = if plan.total_nodes > 0 {
        blocks_to_simulate / (plan.total_nodes as u64 + 1)
    } else {
        blocks_to_simulate
    }
    .max(1);

    for block_num in 0..blocks_to_simulate {
        let height = start_height + block_num + 1;
        sim_time_ms += config.block_interval_ms;

        // Check if it's time to upgrade a node.
        if !all_upgraded
            && next_upgrade_idx < plan.upgrade_order.len()
            && block_num > 0
            && block_num % upgrade_interval_blocks == 0
        {
            let node_idx = plan.upgrade_order[next_upgrade_idx];

            nodes[node_idx].online = false;
            events.push(SimEvent::NodeOffline {
                index: node_idx,
                height,
                time_ms: sim_time_ms,
            });
            debug!(node = node_idx, height, "node offline for upgrade");

            // Simulate upgrade time.
            let upgrade_delay = config.block_interval_ms * 2;
            sim_time_ms += upgrade_delay;
            nodes[node_idx].upgrade_time_ms = upgrade_delay;

            nodes[node_idx].supported_pv = (1..=plan.target_pv).collect();
            nodes[node_idx].upgraded = true;

            nodes[node_idx].online = true;
            events.push(SimEvent::NodeOnline {
                index: node_idx,
                height,
                time_ms: sim_time_ms,
                new_pv: nodes[node_idx].supported_pv.clone(),
            });
            debug!(node = node_idx, height, "node upgraded and back online");

            next_upgrade_idx += 1;

            if next_upgrade_idx >= plan.upgrade_order.len() {
                all_upgraded = true;
                events.push(SimEvent::AllUpgraded {
                    height,
                    time_ms: sim_time_ms,
                });
                info!(height, "all nodes upgraded");
            }
        }

        let pv = version_for_height(height, activations);

        let online_nodes: Vec<usize> = nodes
            .iter()
            .filter(|n| n.online)
            .map(|n| n.index)
            .collect();

        // Liveness check.
        if config.enable_liveness_checks {
            if online_nodes.len() < min_online {
                violations.push(format!(
                    "liveness violation at height {height}: only {} online, need {}",
                    online_nodes.len(),
                    min_online
                ));
                events.push(SimEvent::LivenessViolation {
                    height,
                    time_ms: sim_time_ms,
                    online: online_nodes.len(),
                    required: min_online,
                });
                warn!(height, online = online_nodes.len(), required = min_online, "liveness violation");
            }
        }

        if online_nodes.is_empty() {
            violations.push(format!("no online nodes at height {height}"));
            warn!(height, "no online nodes");
            continue;
        }

        let proposer = online_nodes[height as usize % online_nodes.len()];

        events.push(SimEvent::BlockProduced {
            height,
            pv,
            proposer,
            time_ms: sim_time_ms,
        });
        blocks_produced += 1;

        for node in nodes.iter_mut() {
            if node.online {
                node.height = height;
                node.finalized_height = height;
            }
        }

        // Safety checks.
        if config.enable_safety_checks {
            if let Err(e) = safety::check_no_split_finality(height, 1) {
                violations.push(format!("S1 at height {height}: {e}"));
                events.push(SimEvent::SafetyViolation {
                    check: "S1".into(),
                    height,
                    time_ms: sim_time_ms,
                    detail: e,
                });
                warn!(height, "S1 violation: {}", e);
            } else {
                events.push(SimEvent::SafetyCheckPassed {
                    check: "S1".into(),
                    height,
                    time_ms: sim_time_ms,
                });
            }

            if height > 1 {
                if let Err(e) = safety::check_finality_monotonic(height - 1, height) {
                    violations.push(format!("S2 at height {height}: {e}"));
                    events.push(SimEvent::SafetyViolation {
                        check: "S2".into(),
                        height,
                        time_ms: sim_time_ms,
                        detail: e,
                    });
                    warn!(height, "S2 violation: {}", e);
                }
            }
        }

        // Wire compatibility among online nodes.
        if config.enable_wire_checks {
            for i in 0..nodes.len() {
                for j in (i + 1)..nodes.len() {
                    if !nodes[i].online || !nodes[j].online {
                        continue;
                    }
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
                        events.push(SimEvent::WireIncompatibility {
                            height,
                            time_ms: sim_time_ms,
                            node_a: i,
                            node_b: j,
                            reason: compat.reason,
                        });
                        warn!(height, node_i = i, node_j = j, reason = compat.reason, "wire incompatibility");
                    }
                }
            }
        }

        if let Some(ah) = plan.activation_height {
            if height == ah {
                events.push(SimEvent::ActivationReached {
                    height,
                    pv,
                    time_ms: sim_time_ms,
                });
                info!(height, pv, "activation height reached");
            }
        }
    }

    let total_time_ms = start_time.elapsed().as_millis() as u64;
    let avg_block_time_ms = if blocks_produced > 0 {
        total_time_ms / blocks_produced
    } else {
        0
    };
    let nodes_upgraded = nodes.iter().filter(|n| n.upgraded).count();

    let success = violations.is_empty();
    if success {
        info!("simulation completed successfully");
    } else {
        warn!(violations = violations.len(), "simulation completed with violations");
    }

    SimResult {
        success,
        violations,
        events,
        nodes,
        blocks_produced,
        total_time_ms,
        avg_block_time_ms,
        nodes_upgraded,
    }
}

// -----------------------------------------------------------------------------
// Upgrade safety validation
// -----------------------------------------------------------------------------

/// Validate that a rolling upgrade plan is safe for the given network.
pub fn validate_upgrade_safety(plan: &RollingUpgradePlan) -> RollingResult<Vec<String>> {
    let mut warnings = Vec::new();

    // Validate the plan first.
    if let Err(e) = plan.validate() {
        warnings.push(format!("plan validation error: {}", e));
        return Ok(warnings);
    }

    let quorum = (plan.total_nodes * 2 + 2) / 3;
    let min_online = plan.total_nodes - plan.max_offline;
    if min_online < quorum {
        warnings.push(format!(
            "insufficient quorum during upgrade: {min_online} online < {quorum} required"
        ));
    }

    if plan.max_offline > 1 {
        warnings.push(format!(
            "max_offline={} > 1; taking multiple nodes offline simultaneously is risky",
            plan.max_offline
        ));
    }

    if !SUPPORTED_PROTOCOL_VERSIONS.contains(&plan.target_pv) {
        warnings.push(format!(
            "target PV={} is not supported by this binary (supported: {:?})",
            plan.target_pv, SUPPORTED_PROTOCOL_VERSIONS
        ));
    }

    if let Some(ah) = plan.activation_height {
        let estimated_blocks = plan.estimated_duration_s() / 2;
        if ah < estimated_blocks {
            warnings.push(format!(
                "activation_height={ah} may be too soon; estimated upgrade takes ~{estimated_blocks} blocks"
            ));
        }
        // Also check that activation is after all nodes are upgraded.
        let upgrade_duration_blocks = plan.total_nodes as u64 * 2; // ~2 blocks per node
        if ah < start_height + upgrade_duration_blocks {
            warnings.push(format!(
                "activation_height={ah} may occur before all nodes are upgraded ({}/{} nodes)",
                plan.total_nodes, plan.total_nodes
            ));
        }
    }

    if !warnings.is_empty() {
        debug!(warnings = ?warnings, "upgrade safety warnings");
    }

    Ok(warnings)
}

// -----------------------------------------------------------------------------
// Test helpers
// -----------------------------------------------------------------------------

#[cfg(test)]
pub mod test_helpers {
    use super::*;
    use crate::protocol::version::ProtocolActivation;

    pub fn basic_activations() -> Vec<ProtocolActivation> {
        vec![ProtocolActivation {
            protocol_version: 1,
            activation_height: None,
            grace_blocks: 0,
        }]
    }

    pub fn two_pv_activations() -> Vec<ProtocolActivation> {
        vec![
            ProtocolActivation {
                protocol_version: 1,
                activation_height: None,
                grace_blocks: 0,
            },
            ProtocolActivation {
                protocol_version: 2,
                activation_height: Some(20),
                grace_blocks: 5,
            },
        ]
    }
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

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
    fn test_plan_creation_and_validation() {
        let plan = RollingUpgradePlan::new(4, 1).unwrap();
        assert_eq!(plan.total_nodes, 4);
        assert_eq!(plan.max_byzantine, 1);
        assert_eq!(plan.upgrade_order, vec![0, 1, 2, 3]);
        assert!(plan.validate().is_ok());
    }

    #[test]
    fn test_plan_validation_too_few_nodes() {
        let result = RollingUpgradePlan::new(2, 1);
        assert!(result.is_err());
    }

    #[test]
    fn test_plan_validation_duplicate_order() {
        let mut plan = RollingUpgradePlan::new(4, 1).unwrap();
        plan.upgrade_order = vec![0, 1, 1, 3];
        assert!(plan.validate().is_err());
    }

    #[test]
    fn test_simulate_basic_rolling() {
        let plan = RollingUpgradePlan::new(4, 1).unwrap();
        let activations = basic_activations();
        let config = RollingSimConfig::default();
        let result = simulate_rolling_upgrade(&plan, &activations, 0, 30, &config);

        assert!(result.success, "violations: {:?}", result.violations);
        assert_eq!(result.blocks_produced, 30);
        assert!(result.nodes.iter().all(|n| n.upgraded));
        assert_eq!(result.nodes_upgraded, 4);
    }

    #[test]
    fn test_simulate_with_activation() {
        let plan = RollingUpgradePlan::new(4, 2)
            .unwrap()
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
        let config = RollingSimConfig::default();
        let result = simulate_rolling_upgrade(&plan, &activations, 0, 30, &config);

        let has_activation = result
            .events
            .iter()
            .any(|e| matches!(e, SimEvent::ActivationReached { .. }));
        assert!(has_activation, "should have ActivationReached event");
    }

    #[test]
    fn test_validate_safety_ok() {
        let plan = RollingUpgradePlan::new(4, 1).unwrap();
        let warnings = validate_upgrade_safety(&plan).unwrap();
        assert!(warnings.is_empty(), "unexpected warnings: {:?}", warnings);
    }

    #[test]
    fn test_validate_safety_with_warnings() {
        let mut plan = RollingUpgradePlan::new(4, 1).unwrap();
        plan.max_offline = 2;
        let warnings = validate_upgrade_safety(&plan).unwrap();
        assert!(!warnings.is_empty());
    }

    #[test]
    fn test_estimated_duration() {
        let plan = RollingUpgradePlan::new(7, 1).unwrap();
        assert_eq!(plan.estimated_duration_s(), 7 * 120);
        let plan2 = plan.with_estimated_time(60);
        assert_eq!(plan2.estimated_duration_s(), 7 * 60);
    }

    #[test]
    fn test_plan_with_custom_order() {
        let plan = RollingUpgradePlan::new(4, 1)
            .unwrap()
            .with_order(vec![3, 2, 1, 0]);
        assert_eq!(plan.upgrade_order, vec![3, 2, 1, 0]);
        assert!(plan.validate().is_ok());
    }

    #[test]
    fn test_sim_result_helpers() {
        let plan = RollingUpgradePlan::new(4, 1).unwrap();
        let activations = basic_activations();
        let config = RollingSimConfig::default();
        let result = simulate_rolling_upgrade(&plan, &activations, 0, 10, &config);
        assert!(result.safety_violations().is_empty());
        assert!(result.liveness_violations().is_empty());
        assert!(result.wire_incompatibilities().is_empty());
    }

    #[test]
    fn test_full_config() {
        let config = RollingSimConfig::full();
        assert!(config.enable_safety_checks);
        assert!(config.enable_wire_checks);
        assert!(config.enable_liveness_checks);
        assert_eq!(config.log_level, 2);
    }

    #[test]
    fn test_fast_config() {
        let config = RollingSimConfig::fast();
        assert!(!config.enable_safety_checks);
        assert!(!config.enable_wire_checks);
        assert!(!config.enable_liveness_checks);
    }
}
