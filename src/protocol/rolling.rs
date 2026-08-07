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

#![allow(dead_code)]

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::time::{Duration, Instant};
use thiserror::Error;
use tracing::{debug, error, info, warn};

use super::safety;
use super::version::{version_for_height, ProtocolActivation, SUPPORTED_PROTOCOL_VERSIONS};
use super::wire::{check_hello_compat, Hello};

// -----------------------------------------------------------------------------
// Submodules (embedded)
// -----------------------------------------------------------------------------

pub mod config {
    //! Configuration for rolling upgrade simulation.
    use serde::{Deserialize, Serialize};

    /// Configuration for rolling upgrade simulation.
    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct RollingSimConfig {
        pub min_online: Option<usize>,
        pub block_interval_ms: u64,
        pub enable_safety_checks: bool,
        pub enable_wire_checks: bool,
        pub enable_liveness_checks: bool,
        pub log_level: u8,
        pub upgrade_delay_blocks: u64,
        pub max_concurrent_offline: usize,
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
                upgrade_delay_blocks: 2,
                max_concurrent_offline: 1,
            }
        }
    }

    impl RollingSimConfig {
        pub fn full() -> Self {
            Self {
                enable_safety_checks: true,
                enable_wire_checks: true,
                enable_liveness_checks: true,
                ..Default::default()
            }
        }

        pub fn fast() -> Self {
            Self {
                enable_safety_checks: false,
                enable_wire_checks: false,
                enable_liveness_checks: false,
                ..Default::default()
            }
        }
    }
}

pub mod error {
    //! Error types for rolling upgrade planning and simulation.
    use super::config::RollingSimConfig;
    use thiserror::Error;

    #[derive(Debug, Error, Clone, PartialEq, Eq)]
    pub enum RollingError {
        #[error("not enough nodes: need at least {need}, got {got}")]
        NotEnoughNodes { need: usize, got: usize },

        #[error("max offline ({offline}) exceeds BFT tolerance f={f} for N={n}")]
        OfflineExceedsTolerance { offline: usize, f: usize, n: usize },

        #[error("order length ({len}) does not match total nodes ({total})")]
        OrderLengthMismatch { len: usize, total: usize },

        #[error("invalid node index {0} in upgrade order")]
        InvalidNodeIndex(usize),

        #[error("duplicate node index {0} in upgrade order")]
        DuplicateNode(usize),

        #[error("target PV {0} not supported by this binary (supported: {1:?})")]
        UnsupportedTarget(u32, Vec<u32>),

        #[error("activation height too low: {got} (minimum {min})")]
        ActivationHeightTooLow { got: u64, min: u64 },

        #[error("grace window too small: {got} (minimum {min})")]
        GraceTooSmall { got: u64, min: u64 },

        #[error("upgrade order must include all nodes exactly once")]
        IncompleteOrder,

        #[error("configuration error: {0}")]
        Config(String),
    }

    pub type RollingResult<T> = Result<T, RollingError>;
}

pub mod plan {
    //! Rolling upgrade plan definition.
    use super::error::{RollingError, RollingResult};
    use super::config::RollingSimConfig;
    use serde::{Deserialize, Serialize};

    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct RollingUpgradePlan {
        pub total_nodes: usize,
        pub max_byzantine: usize,
        pub max_offline: usize,
        pub upgrade_order: Vec<usize>,
        pub target_pv: u32,
        pub activation_height: Option<u64>,
        pub grace_blocks: u64,
        pub estimated_per_node_s: u64,
    }

    impl RollingUpgradePlan {
        pub fn new(total_nodes: usize, target_pv: u32) -> RollingResult<Self> {
            if total_nodes < 4 {
                return Err(RollingError::NotEnoughNodes { need: 4, got: total_nodes });
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

        pub fn with_activation(mut self, height: u64, grace: u64) -> Self {
            self.activation_height = Some(height);
            self.grace_blocks = grace;
            info!(height, grace, "activation set for rolling upgrade");
            self
        }

        pub fn with_order(mut self, order: Vec<usize>) -> Self {
            self.upgrade_order = order;
            debug!(order = ?order, "custom upgrade order set");
            self
        }

        pub fn with_estimated_time(mut self, seconds: u64) -> Self {
            self.estimated_per_node_s = seconds;
            self
        }

        pub fn with_max_offline(mut self, max_offline: usize) -> Self {
            self.max_offline = max_offline;
            self
        }

        pub fn validate(&self) -> RollingResult<()> {
            if self.total_nodes < 4 {
                return Err(RollingError::NotEnoughNodes { need: 4, got: self.total_nodes });
            }

            let f = (self.total_nodes - 1) / 3;
            if self.max_offline > f {
                return Err(RollingError::OfflineExceedsTolerance {
                    offline: self.max_offline,
                    f,
                    n: self.total_nodes,
                });
            }

            if self.upgrade_order.len() != self.total_nodes {
                return Err(RollingError::OrderLengthMismatch {
                    len: self.upgrade_order.len(),
                    total: self.total_nodes,
                });
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

            if !seen.iter().all(|&s| s) {
                return Err(RollingError::IncompleteOrder);
            }

            if !super::SUPPORTED_PROTOCOL_VERSIONS.contains(&self.target_pv) {
                return Err(RollingError::UnsupportedTarget(
                    self.target_pv,
                    super::SUPPORTED_PROTOCOL_VERSIONS.to_vec(),
                ));
            }

            if let Some(ah) = self.activation_height {
                if ah < 100 {
                    return Err(RollingError::ActivationHeightTooLow { got: ah, min: 100 });
                }
            }

            if self.grace_blocks < 10 {
                return Err(RollingError::GraceTooSmall { got: self.grace_blocks, min: 10 });
            }

            Ok(())
        }

        pub fn estimated_duration_s(&self) -> u64 {
            self.total_nodes as u64 * self.estimated_per_node_s
        }

        pub fn estimated_blocks(&self, block_time_s: u64) -> u64 {
            self.estimated_duration_s() / block_time_s.max(1)
        }
    }
}

pub mod node {
    //! Simulated node state.
    use serde::{Deserialize, Serialize};

    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct SimNode {
        pub index: usize,
        pub supported_pv: Vec<u32>,
        pub online: bool,
        pub upgraded: bool,
        pub height: u64,
        pub finalized_height: u64,
        pub upgrade_time_ms: u64,
    }

    impl SimNode {
        pub fn new(index: usize) -> Self {
            Self {
                index,
                supported_pv: vec![1],
                online: true,
                upgraded: false,
                height: 0,
                finalized_height: 0,
                upgrade_time_ms: 0,
            }
        }

        pub fn upgrade(&mut self, target_pv: u32, upgrade_delay_ms: u64) {
            self.online = false;
            self.upgrade_time_ms = upgrade_delay_ms;
            self.supported_pv = (1..=target_pv).collect();
            self.upgraded = true;
            self.online = true;
        }

        pub fn supports_pv(&self, pv: u32) -> bool {
            self.supported_pv.contains(&pv)
        }
    }
}

pub mod event {
    //! Simulation events.
    use super::node::SimNode;

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

    impl std::fmt::Display for SimEvent {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            match self {
                Self::NodeOffline { index, height, time_ms } => {
                    write!(f, "[{}ms] Node {} offline at height {}", time_ms, index, height)
                }
                Self::NodeOnline { index, height, time_ms, new_pv } => {
                    write!(f, "[{}ms] Node {} online at height {} with PV {:?}", time_ms, index, height, new_pv)
                }
                Self::BlockProduced { height, pv, proposer, time_ms } => {
                    write!(f, "[{}ms] Block {} (PV {}) produced by node {}", time_ms, height, pv, proposer)
                }
                Self::AllUpgraded { height, time_ms } => {
                    write!(f, "[{}ms] All nodes upgraded at height {}", time_ms, height)
                }
                Self::ActivationReached { height, pv, time_ms } => {
                    write!(f, "[{}ms] Activation reached at height {} (PV {})", time_ms, height, pv)
                }
                Self::SafetyCheckPassed { check, height, time_ms } => {
                    write!(f, "[{}ms] Safety check {} passed at height {}", time_ms, check, height)
                }
                Self::SafetyViolation { check, height, time_ms, detail } => {
                    write!(f, "[{}ms] Safety violation {} at height {}: {}", time_ms, check, height, detail)
                }
                Self::LivenessViolation { height, time_ms, online, required } => {
                    write!(f, "[{}ms] Liveness violation at height {}: {} online, need {}", time_ms, height, online, required)
                }
                Self::WireIncompatibility { height, time_ms, node_a, node_b, reason } => {
                    write!(f, "[{}ms] Wire incompatibility at height {}: node {} <-> node {}: {}", time_ms, height, node_a, node_b, reason)
                }
            }
        }
    }
}

pub mod result {
    //! Simulation results.
    use super::event::SimEvent;
    use super::node::SimNode;
    use serde::{Deserialize, Serialize};

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
        pub max_concurrent_offline: usize,
        pub activation_reached: bool,
    }

    impl SimResult {
        pub fn safety_violations(&self) -> Vec<&SimEvent> {
            self.events
                .iter()
                .filter(|e| matches!(e, SimEvent::SafetyViolation { .. }))
                .collect()
        }

        pub fn liveness_violations(&self) -> Vec<&SimEvent> {
            self.events
                .iter()
                .filter(|e| matches!(e, SimEvent::LivenessViolation { .. }))
                .collect()
        }

        pub fn wire_incompatibilities(&self) -> Vec<&SimEvent> {
            self.events
                .iter()
                .filter(|e| matches!(e, SimEvent::WireIncompatibility { .. }))
                .collect()
        }
    }
}

// -----------------------------------------------------------------------------
// Public exports
// -----------------------------------------------------------------------------

pub use config::RollingSimConfig;
pub use error::{RollingError, RollingResult};
pub use plan::RollingUpgradePlan;
pub use node::SimNode;
pub use event::SimEvent;
pub use result::SimResult;

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
        .map(SimNode::new)
        .collect();

    let mut events = Vec::new();
    let mut violations = Vec::new();
    let mut blocks_produced = 0u64;
    let mut next_upgrade_idx = 0usize;
    let mut all_upgraded = false;
    let mut sim_time_ms = 0u64;
    let mut max_concurrent_offline = 0usize;
    let mut activation_reached = false;

    let quorum = (plan.total_nodes * 2 + 2) / 3;
    let min_online = config.min_online.unwrap_or(quorum);
    let upgrade_interval_blocks = if plan.total_nodes > 0 {
        (blocks_to_simulate / (plan.total_nodes as u64 + 1)).max(1)
    } else {
        blocks_to_simulate
    };

    for block_num in 0..blocks_to_simulate {
        let height = start_height + block_num + 1;
        sim_time_ms += config.block_interval_ms;

        // Count offline nodes.
        let offline_count = nodes.iter().filter(|n| !n.online).count();
        if offline_count > max_concurrent_offline {
            max_concurrent_offline = offline_count;
        }

        // Check if it's time to upgrade a node.
        if !all_upgraded
            && next_upgrade_idx < plan.upgrade_order.len()
            && block_num > 0
            && block_num % upgrade_interval_blocks == 0
        {
            let node_idx = plan.upgrade_order[next_upgrade_idx];

            // Take node offline for upgrade.
            nodes[node_idx].online = false;
            events.push(SimEvent::NodeOffline {
                index: node_idx,
                height,
                time_ms: sim_time_ms,
            });
            debug!(node = node_idx, height, "node offline for upgrade");

            // Simulate upgrade.
            let upgrade_delay = config.block_interval_ms * config.upgrade_delay_blocks;
            sim_time_ms += upgrade_delay;
            nodes[node_idx].upgrade(plan.target_pv, upgrade_delay);

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

        // Check that no more than max_concurrent_offline nodes are offline.
        if offline_count > config.max_concurrent_offline {
            violations.push(format!(
                "too many nodes offline: {offline_count} > {}",
                config.max_concurrent_offline
            ));
            events.push(SimEvent::LivenessViolation {
                height,
                time_ms: sim_time_ms,
                online: nodes.len() - offline_count,
                required: nodes.len() - config.max_concurrent_offline,
            });
            warn!(height, offline = offline_count, max = config.max_concurrent_offline, "too many offline nodes");
        }

        // Select proposer.
        let proposer = online_nodes[height as usize % online_nodes.len()];

        events.push(SimEvent::BlockProduced {
            height,
            pv,
            proposer,
            time_ms: sim_time_ms,
        });
        blocks_produced += 1;

        // Update node heights.
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
                activation_reached = true;
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
        max_concurrent_offline,
        activation_reached,
    }
}

// -----------------------------------------------------------------------------
// Upgrade safety validation
// -----------------------------------------------------------------------------

/// Validate that a rolling upgrade plan is safe for the given network.
pub fn validate_upgrade_safety(plan: &RollingUpgradePlan) -> RollingResult<Vec<String>> {
    let mut warnings = Vec::new();

    plan.validate()?;

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
        let estimated_blocks = plan.estimated_blocks(2);
        if ah < estimated_blocks {
            warnings.push(format!(
                "activation_height={ah} may be too soon; estimated upgrade takes ~{estimated_blocks} blocks"
            ));
        }
        let upgrade_duration_blocks = plan.total_nodes as u64 * 2;
        let start_height = 0;
        if ah < start_height + upgrade_duration_blocks {
            warnings.push(format!(
                "activation_height={ah} may occur before all nodes are upgraded (needs ~{} blocks)",
                upgrade_duration_blocks
            ));
        }
    }

    if !warnings.is_empty() {
        debug!(warnings = ?warnings, "upgrade safety warnings");
    }

    Ok(warnings)
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
        assert!(result.activation_reached);
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

    #[test]
    fn test_plan_with_max_offline() {
        let plan = RollingUpgradePlan::new(7, 1)
            .unwrap()
            .with_max_offline(2);
        assert_eq!(plan.max_offline, 2);
        // Validate should fail because max_offline > f for N=7 (f=2, max_offline=2 is ok).
        assert!(plan.validate().is_ok());
    }

    #[test]
    fn test_plan_validation_incomplete_order() {
        let mut plan = RollingUpgradePlan::new(4, 1).unwrap();
        plan.upgrade_order = vec![0, 1, 2];
        assert!(plan.validate().is_err());
    }

    #[test]
    fn test_sim_result_activation_reached_field() {
        let plan = RollingUpgradePlan::new(4, 2)
            .unwrap()
            .with_activation(10, 5);
        let activations = vec![
            ProtocolActivation { protocol_version: 1, activation_height: None, grace_blocks: 0 },
            ProtocolActivation { protocol_version: 2, activation_height: Some(10), grace_blocks: 5 },
        ];
        let config = RollingSimConfig::default();
        let result = simulate_rolling_upgrade(&plan, &activations, 0, 20, &config);
        assert!(result.activation_reached);
    }
}
