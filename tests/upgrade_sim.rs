//! Upgrade simulation tests (UPGRADE_SPEC section 10.1).
//!
//! Simulates a rolling protocol upgrade across multiple nodes and verifies
//! that safety invariants hold throughout the process.
//!
//! # Scenarios
//!
//! 1. **Rolling upgrade (no activation)**: Nodes upgrade one by one; all
//!    continue producing PV=1 blocks. No disruption.
//!
//! 2. **Activation at height H**: After rolling upgrade, nodes switch to
//!    PV=2 at the activation height. Grace window tested.
//!
//! 3. **Invariant checks**: No split finality, monotonic finality,
//!    deterministic PV selection, state compatibility.

use iona::protocol::dual_validate::ShadowValidator;
use iona::protocol::safety::{
    check_finality_monotonic, check_no_split_finality, check_root_equivalence,
    check_value_conservation,
};
use iona::protocol::version::{
    default_activations, validate_block_version, version_for_height, ProtocolActivation,
    CURRENT_PROTOCOL_VERSION, SUPPORTED_PROTOCOL_VERSIONS,
};
use iona::protocol::wire::{check_hello_compat, Hello};
use iona::types::{receipts_root, tx_root, Block, BlockHeader, Hash32};

// -----------------------------------------------------------------------------
// Constants
// -----------------------------------------------------------------------------

/// IONA testnet chain ID.
const CHAIN_ID: u64 = 6126151;

/// Genesis hash placeholder.
const GENESIS_HASH: Hash32 = Hash32::zero();

/// Software version string used in `Hello` messages.
const SOFTWARE_VERSION: &str = "27.1.0";

/// Default block timestamp increment.
const TIMESTAMP_BASE: u64 = 1000;

/// Number of nodes in rolling upgrade tests.
const NUM_NODES: usize = 5;

/// Number of blocks to simulate in rolling upgrade.
const NUM_BLOCKS: usize = 20;

/// Height thresholds for upgrading nodes (1‑based).
const UPGRADE_NODE0_AT: u64 = 5;
const UPGRADE_NODE1_AT: u64 = 8;
const UPGRADE_NODE2_AT: u64 = 11;
const UPGRADE_NODE3_AT: u64 = 14;
const UPGRADE_NODE4_AT: u64 = 17;

/// Activation height for PV=2.
const ACTIVATION_HEIGHT: u64 = 10;

/// Grace window length (blocks) after activation.
const GRACE_WINDOW: u64 = 3;

/// End of grace window = ACTIVATION_HEIGHT + GRACE_WINDOW - 1.
const GRACE_END: u64 = ACTIVATION_HEIGHT + GRACE_WINDOW - 1;

/// Future schema version for rejection tests.
const FUTURE_SCHEMA_VERSION: u32 = 999;

/// Default protocol version 1.
const PV_1: u32 = 1;

/// Protocol version 2.
const PV_2: u32 = 2;

/// Supported schema versions list (for `Hello` messages).
const SUPPORTED_SCHEMA_VERSIONS: &[u32] = &[0, 1, 2, 3, 4];

/// Head height used in `Hello` messages.
const HELLO_HEAD_HEIGHT: u64 = 100;

/// Head protocol version used in `Hello` messages.
const HELLO_HEAD_PV: u32 = 1;

// -----------------------------------------------------------------------------
// Helpers
// -----------------------------------------------------------------------------

/// Create a minimal block with the given height and protocol version.
fn make_block(height: u64, protocol_version: u32) -> Block {
    let txs = vec![];
    Block {
        header: BlockHeader {
            height,
            round: 0,
            prev: Hash32::zero(),
            proposer_pk: vec![1, 2, 3],
            tx_root: tx_root(&txs),
            receipts_root: receipts_root(&[]),
            state_root: Hash32::zero(),
            base_fee_per_gas: 1,
            gas_used: 0,
            intrinsic_gas_used: 0,
            exec_gas_used: 0,
            vm_gas_used: 0,
            evm_gas_used: 0,
            chain_id: CHAIN_ID,
            timestamp: TIMESTAMP_BASE + height,
            protocol_version,
        },
        txs,
    }
}

/// Create a `Hello` handshake message with a given set of supported protocol versions.
fn make_hello(supported_pv: Vec<u32>) -> Hello {
    Hello {
        supported_pv,
        supported_sv: SUPPORTED_SCHEMA_VERSIONS.to_vec(),
        software_version: SOFTWARE_VERSION.into(),
        chain_id: CHAIN_ID,
        genesis_hash: GENESIS_HASH,
        head_height: HELLO_HEAD_HEIGHT,
        head_pv: HELLO_HEAD_PV,
    }
}

/// Create the activation schedule used in most tests.
fn standard_activations() -> Vec<ProtocolActivation> {
    default_activations()
}

/// Create an activation schedule with PV=2 activation at a specific height.
fn activations_with_pv2_at(activation_height: u64, grace_blocks: u64) -> Vec<ProtocolActivation> {
    vec![
        ProtocolActivation {
            protocol_version: PV_1,
            activation_height: None,
            grace_blocks: 0,
        },
        ProtocolActivation {
            protocol_version: PV_2,
            activation_height: Some(activation_height),
            grace_blocks,
        },
    ]
}

/// Check that all pairs of nodes are compatible (handshake passes).
fn assert_all_pairs_compatible(node_pvs: &[Vec<u32>]) {
    let n = node_pvs.len();
    for i in 0..n {
        for j in 0..n {
            if i == j {
                continue;
            }
            let hello_i = make_hello(node_pvs[i].clone());
            let hello_j = make_hello(node_pvs[j].clone());
            let result = check_hello_compat(&hello_i, &hello_j);
            assert!(
                result.compatible,
                "nodes {} and {} (PVs {:?} vs {:?}) are incompatible",
                i, j, node_pvs[i], node_pvs[j]
            );
        }
    }
}

// -----------------------------------------------------------------------------
// 10.1: Upgrade simulation tests
// -----------------------------------------------------------------------------

/// Simulate a 5‑node network where nodes upgrade one by one (rolling).
/// All produce PV=1 blocks throughout (no activation height).
#[test]
fn upgrade_sim_rolling_no_activation() {
    let activations = standard_activations();
    let mut node_pvs: Vec<Vec<u32>> = vec![vec![PV_1]; NUM_NODES];
    let mut finalized_height = 0;

    for height in 1..=NUM_BLOCKS as u64 {
        // Simulate node upgrades at specific heights.
        if height == UPGRADE_NODE0_AT {
            node_pvs[0] = vec![PV_1]; // still only PV=1
        }
        if height == UPGRADE_NODE1_AT {
            node_pvs[1] = vec![PV_1];
        }
        if height == UPGRADE_NODE2_AT {
            node_pvs[2] = vec![PV_1];
        }
        if height == UPGRADE_NODE3_AT {
            node_pvs[3] = vec![PV_1];
        }
        if height == UPGRADE_NODE4_AT {
            node_pvs[4] = vec![PV_1];
        }

        let expected_pv = version_for_height(height, &activations);
        assert_eq!(
            expected_pv, PV_1,
            "PV should be 1 without activation at height {}",
            height
        );

        let block = make_block(height, expected_pv);
        assert!(
            validate_block_version(block.header.protocol_version, height, &activations).is_ok(),
            "block at height {} should be valid",
            height
        );

        assert!(check_no_split_finality(height, 1).is_ok());
        assert!(check_finality_monotonic(finalized_height, height).is_ok());
        finalized_height = height;
    }
}

/// Simulate activation at height H=10 with grace window G=3.
#[test]
fn upgrade_sim_activation_with_grace() {
    let activations = activations_with_pv2_at(ACTIVATION_HEIGHT, GRACE_WINDOW);

    for height in 1..=20 {
        let expected_pv = version_for_height(height, &activations);

        if height < ACTIVATION_HEIGHT {
            assert_eq!(
                expected_pv, PV_1,
                "before activation: PV should be 1 at height {}",
                height
            );
            assert!(validate_block_version(PV_1, height, &activations).is_ok());
        } else {
            assert_eq!(
                expected_pv, PV_2,
                "after activation: PV should be 2 at height {}",
                height
            );

            if height < GRACE_END + 1 {
                // During grace window, PV=1 is still accepted.
                assert!(
                    validate_block_version(PV_1, height, &activations).is_ok(),
                    "PV=1 should be accepted in grace window at height {}",
                    height
                );
            }
        }
    }
}

/// Verify PV is deterministic: same height + same activations = same PV.
#[test]
fn upgrade_sim_deterministic_pv() {
    let activations = activations_with_pv2_at(50, 10);
    let heights = [1, 49, 50, 51, 59, 60, 100];

    for &height in &heights {
        let first = version_for_height(height, &activations);
        for _ in 0..1000 {
            let current = version_for_height(height, &activations);
            assert_eq!(
                current, first,
                "PV must be deterministic for height {}",
                height
            );
        }
    }
}

/// Verify finality monotonicity invariant.
#[test]
fn upgrade_sim_finality_monotonic() {
    let mut prev = 0;
    for h in 1..=100 {
        assert!(check_finality_monotonic(prev, h).is_ok());
        prev = h;
    }
    // Regression: going backward should fail.
    assert!(check_finality_monotonic(100, 99).is_err());
}

/// Verify no‑split‑finality invariant.
#[test]
fn upgrade_sim_no_split_finality() {
    assert!(check_no_split_finality(1, 0).is_ok());
    assert!(check_no_split_finality(1, 1).is_ok());
    assert!(check_no_split_finality(1, 2).is_err());
    assert!(check_no_split_finality(1, 3).is_err());
}

/// Verify value conservation invariant.
#[test]
fn upgrade_sim_value_conservation() {
    // 1000 initial + 10 minted - 3 slashed - 2 burned = 1005 final.
    assert!(check_value_conservation(1000, 1005, 10, 3, 2).is_ok());
    // Violation: final supply does not match.
    assert!(check_value_conservation(1000, 1010, 5, 0, 0).is_err());
}

/// Verify root equivalence for format‑only migrations.
#[test]
fn upgrade_sim_root_equivalence() {
    let root = [42u8; 32];
    let other = [43u8; 32];
    assert!(check_root_equivalence(&root, &root).is_ok());
    assert!(check_root_equivalence(&root, &other).is_err());
}

// -----------------------------------------------------------------------------
// 10.2: Handshake / compatibility tests
// -----------------------------------------------------------------------------

/// Simulate handshake between nodes with different PV support.
#[test]
fn upgrade_sim_handshake_compat() {
    let compat = |a: Vec<u32>, b: Vec<u32>| -> bool {
        check_hello_compat(&make_hello(a), &make_hello(b)).compatible
    };

    // Same version → compatible.
    assert!(compat(vec![PV_1], vec![PV_1]));
    // One upgraded → compatible at PV=1.
    assert!(compat(vec![PV_1], vec![PV_1, PV_2]));
    // Both upgraded → compatible at PV=2.
    assert!(compat(vec![PV_1, PV_2], vec![PV_1, PV_2]));
    // No overlap → incompatible.
    assert!(!compat(vec![PV_1], vec![PV_2]));
}

/// Simulate rolling upgrade with handshake compatibility at each step.
#[test]
fn upgrade_sim_rolling_handshake() {
    // All nodes start with only PV=1.
    let mut node_pvs: Vec<Vec<u32>> = vec![vec![PV_1]; NUM_NODES];
    assert_all_pairs_compatible(&node_pvs);

    // Upgrade nodes one by one (add PV=2 support).
    for idx in 0..NUM_NODES {
        node_pvs[idx] = vec![PV_1, PV_2];
        assert_all_pairs_compatible(&node_pvs);
    }
}

// -----------------------------------------------------------------------------
// 10.3: Shadow validation tests
// -----------------------------------------------------------------------------

/// Shadow validator should not interfere with current‑PV blocks.
#[test]
fn upgrade_sim_shadow_validation_noop() {
    let activations = vec![ProtocolActivation {
        protocol_version: PV_1,
        activation_height: None,
        grace_blocks: 0,
    }];
    let shadow = ShadowValidator::new(activations);

    for h in 1..=10 {
        let block = make_block(h, PV_1);
        let result = shadow.validate(&block, h);
        assert!(result.is_ok(), "shadow validation should not error at height {}", h);
    }

    let stats = shadow.stats();
    // With only PV=1, no shadow validation failures are expected.
    assert_eq!(stats.failed, 0, "shadow failures unexpected");
}

/// Multiple nodes processing the same blocks must get identical PV sequences.
#[test]
fn upgrade_sim_multi_node_determinism() {
    let activations = standard_activations();
    let num_nodes = 3;
    let num_blocks = 50;
    let mut results = vec![vec![]; num_nodes];

    for node in 0..num_nodes {
        for height in 1..=num_blocks {
            let pv = version_for_height(height, &activations);
            results[node].push(pv);
        }
    }

    for i in 1..num_nodes {
        assert_eq!(
            results[0], results[i],
            "node 0 and node {} disagree on PV sequence",
            i
        );
    }
}

// -----------------------------------------------------------------------------
// 10.4: Migration conformance
// -----------------------------------------------------------------------------

/// Verify that `NodeMeta` can be created, saved, loaded, and checked.
#[test]
fn upgrade_sim_meta_roundtrip() {
    use iona::storage::meta::NodeMeta;
    let dir = tempfile::tempdir().unwrap();
    let data_dir = dir.path().to_str().unwrap();

    let mut meta = NodeMeta::new_current();
    assert!(!meta.has_pending_migration());

    meta.save(data_dir).unwrap();
    let loaded = NodeMeta::load(data_dir).unwrap().unwrap();
    assert_eq!(loaded.schema_version, meta.schema_version);
    assert_eq!(loaded.protocol_version, meta.protocol_version);
    assert!(loaded.check_compatibility().is_ok());
}

/// Verify migration state persistence for crash‑safe resume.
#[test]
fn upgrade_sim_migration_crash_safe() {
    use iona::storage::meta::NodeMeta;
    let dir = tempfile::tempdir().unwrap();
    let data_dir = dir.path().to_str().unwrap();

    let mut meta = NodeMeta::new_current();
    meta.save(data_dir).unwrap();

    meta.begin_migration(3, 4, "test migration", data_dir).unwrap();
    assert!(meta.has_pending_migration());

    // Simulate crash: reload from disk.
    let reloaded = NodeMeta::load(data_dir).unwrap().unwrap();
    assert!(reloaded.has_pending_migration());
    let ms = reloaded.migration_state.unwrap();
    assert_eq!(ms.from_sv, 3);
    assert_eq!(ms.to_sv, 4);

    meta.end_migration(data_dir).unwrap();
    let reloaded2 = NodeMeta::load(data_dir).unwrap().unwrap();
    assert!(!reloaded2.has_pending_migration());
}

/// Verify that future schema versions are rejected.
#[test]
fn upgrade_sim_future_schema_rejected() {
    use iona::storage::meta::NodeMeta;
    let meta = NodeMeta {
        schema_version: FUTURE_SCHEMA_VERSION,
        protocol_version: PV_1,
        node_version: "99.0.0".into(),
        updated_at: None,
        migration_state: None,
    };
    assert!(meta.check_compatibility().is_err());
}
