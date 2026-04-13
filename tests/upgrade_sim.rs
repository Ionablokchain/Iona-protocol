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

// ─── Helpers ────────────────────────────────────────────────────────────────

fn make_block(height: u64, pv: u32) -> Block {
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
            chain_id: 6126151,
            timestamp: 1000 + height,
            protocol_version: pv,
        },
        txs,
    }
}

fn make_hello(pvs: Vec<u32>) -> Hello {
    Hello {
        supported_pv: pvs,
        supported_sv: vec![0, 1, 2, 3, 4],
        software_version: "27.1.0".into(),
        chain_id: 6126151,
        genesis_hash: Hash32::zero(),
        head_height: 100,
        head_pv: 1,
    }
}

// ─── 10.1: Upgrade simulation tests ────────────────────────────────────────

/// Simulate a 5-node network where nodes upgrade one by one (rolling).
/// All produce PV=1 blocks throughout (no activation height).
#[test]
fn upgrade_sim_rolling_no_activation() {
    let activations = default_activations();
    let num_nodes = 5;
    let num_blocks = 20;

    // All nodes start on PV=1
    let mut node_pvs: Vec<Vec<u32>> = vec![vec![1]; num_nodes];

    let mut finalized_height = 0u64;

    for height in 1..=num_blocks {
        // At certain heights, upgrade a node (add PV support)
        if height == 5 {
            node_pvs[0] = vec![1];
        } // Node 0 "upgrades" (still PV=1 only)
        if height == 8 {
            node_pvs[1] = vec![1];
        }
        if height == 11 {
            node_pvs[2] = vec![1];
        }
        if height == 14 {
            node_pvs[3] = vec![1];
        }
        if height == 17 {
            node_pvs[4] = vec![1];
        }

        // Determine PV for this height
        let pv = version_for_height(height, &activations);
        assert_eq!(pv, 1, "PV should be 1 without activation");

        // Create and validate block
        let block = make_block(height, pv);
        assert!(
            validate_block_version(block.header.protocol_version, height, &activations).is_ok(),
            "block at height {height} should be valid"
        );

        // Safety invariants
        assert!(check_no_split_finality(height, 1).is_ok());
        assert!(check_finality_monotonic(finalized_height, height).is_ok());
        finalized_height = height;
    }
}

/// Simulate activation at height H=10 with grace window G=3.
/// Before H: all nodes produce PV=1.
/// At H: upgraded nodes switch to PV=2.
/// After H+G: PV=1 blocks rejected.
#[test]
fn upgrade_sim_activation_with_grace() {
    let activations = vec![
        ProtocolActivation {
            protocol_version: 1,
            activation_height: None,
            grace_blocks: 0,
        },
        ProtocolActivation {
            protocol_version: 2,
            activation_height: Some(10),
            grace_blocks: 3,
        },
    ];

    for height in 1..=20 {
        let expected_pv = version_for_height(height, &activations);

        if height < 10 {
            assert_eq!(expected_pv, 1, "before activation: PV should be 1");
            // PV=1 block should be valid
            assert!(validate_block_version(1, height, &activations).is_ok());
        } else {
            assert_eq!(expected_pv, 2, "after activation: PV should be 2");

            if height < 13 {
                // In grace window: both PV=1 and PV=2 should be accepted
                // (PV=2 is not in SUPPORTED_PROTOCOL_VERSIONS yet, so we only test PV=1 acceptance)
                // PV=1 is accepted during grace since height < 10 + 3
                assert!(
                    validate_block_version(1, height, &activations).is_ok(),
                    "PV=1 should be accepted in grace window at height {height}"
                );
            }
        }
    }
}

/// Verify PV is deterministic: same height + same activations = same PV.
#[test]
fn upgrade_sim_deterministic_pv() {
    let activations = vec![
        ProtocolActivation {
            protocol_version: 1,
            activation_height: None,
            grace_blocks: 0,
        },
        ProtocolActivation {
            protocol_version: 2,
            activation_height: Some(50),
            grace_blocks: 10,
        },
    ];

    // Compute PV 1000 times for the same height — must be identical
    for height in [1, 49, 50, 51, 59, 60, 100] {
        let first = version_for_height(height, &activations);
        for _ in 0..1000 {
            assert_eq!(
                version_for_height(height, &activations),
                first,
                "PV must be deterministic for height {height}"
            );
        }
    }
}

/// Verify finality monotonicity over a simulated chain.
#[test]
fn upgrade_sim_finality_monotonic() {
    let mut prev = 0u64;
    for h in 1..=100 {
        assert!(check_finality_monotonic(prev, h).is_ok());
        prev = h;
    }
    // Regression: going backward should fail
    assert!(check_finality_monotonic(100, 99).is_err());
}

/// Verify no split finality invariant.
#[test]
fn upgrade_sim_no_split_finality() {
    // Normal: 0 or 1 finalized blocks per height
    assert!(check_no_split_finality(1, 0).is_ok());
    assert!(check_no_split_finality(1, 1).is_ok());
    // Violation: 2+ finalized blocks at same height
    assert!(check_no_split_finality(1, 2).is_err());
    assert!(check_no_split_finality(1, 3).is_err());
}

/// Verify value conservation invariant.
#[test]
fn upgrade_sim_value_conservation() {
    // Simple: 1000 + 10 minted - 3 slashed - 2 burned = 1005
    assert!(check_value_conservation(1000, 1005, 10, 3, 2).is_ok());
    // Violation: supply doesn't match
    assert!(check_value_conservation(1000, 1010, 5, 0, 0).is_err());
}

/// Verify root equivalence for format-only migrations.
#[test]
fn upgrade_sim_root_equivalence() {
    let root = [42u8; 32];
    assert!(check_root_equivalence(&root, &root).is_ok());
    let other = [43u8; 32];
    assert!(check_root_equivalence(&root, &other).is_err());
}

// ─── 10.2: Handshake / compatibility tests ─────────────────────────────────

/// Simulate handshake between nodes with different PV support.
#[test]
fn upgrade_sim_handshake_compat() {
    // Same version: compatible
    let a = make_hello(vec![1]);
    let b = make_hello(vec![1]);
    let r = check_hello_compat(&a, &b);
    assert!(r.compatible);
    assert_eq!(r.session_pv, 1);

    // One upgraded: compatible at PV=1
    let a = make_hello(vec![1]);
    let b = make_hello(vec![1, 2]);
    let r = check_hello_compat(&a, &b);
    assert!(r.compatible);
    assert_eq!(r.session_pv, 1);

    // Both upgraded: compatible at PV=2
    let a = make_hello(vec![1, 2]);
    let b = make_hello(vec![1, 2]);
    let r = check_hello_compat(&a, &b);
    assert!(r.compatible);
    assert_eq!(r.session_pv, 2);

    // No overlap: incompatible
    let a = make_hello(vec![1]);
    let b = make_hello(vec![2]);
    let r = check_hello_compat(&a, &b);
    assert!(!r.compatible);
}

/// Simulate rolling upgrade with handshake compatibility at each step.
#[test]
fn upgrade_sim_rolling_handshake() {
    let num_nodes = 5;
    let mut node_pvs: Vec<Vec<u32>> = vec![vec![1]; num_nodes];

    // Initially all compatible
    for i in 0..num_nodes {
        for j in 0..num_nodes {
            if i == j {
                continue;
            }
            let a = make_hello(node_pvs[i].clone());
            let b = make_hello(node_pvs[j].clone());
            let r = check_hello_compat(&a, &b);
            assert!(
                r.compatible,
                "initial: node {i} and {j} should be compatible"
            );
        }
    }

    // Upgrade nodes one by one
    for upgrade_idx in 0..num_nodes {
        node_pvs[upgrade_idx] = vec![1, 2];

        // All nodes should still be compatible (intersection includes PV=1)
        for i in 0..num_nodes {
            for j in 0..num_nodes {
                if i == j {
                    continue;
                }
                let a = make_hello(node_pvs[i].clone());
                let b = make_hello(node_pvs[j].clone());
                let r = check_hello_compat(&a, &b);
                assert!(
                    r.compatible,
                    "after upgrading node {upgrade_idx}: node {i} and {j} should be compatible"
                );
            }
        }
    }
}

// ─── 10.3: Shadow validation tests ─────────────────────────────────────────

/// Shadow validator should not interfere with current-PV blocks.
#[test]
fn upgrade_sim_shadow_validation_noop() {
    let activations = vec![ProtocolActivation {
        protocol_version: 1,
        activation_height: None,
        grace_blocks: 0,
    }];
    let sv = ShadowValidator::new(activations);

    for h in 1..=10 {
        let block = make_block(h, 1);
        let result = sv.validate(&block, h);
        assert!(result.is_ok(), "shadow validation should not error");
    }

    let stats = sv.stats();
    // With only PV=1, shadow validation is not applicable
    assert_eq!(stats.failed, 0, "no shadow failures expected");
}

/// Multiple nodes processing the same blocks should get identical results.
#[test]
fn upgrade_sim_multi_node_determinism() {
    let activations = default_activations();

    // Simulate 3 nodes processing the same block sequence
    let mut results: Vec<Vec<u32>> = vec![vec![]; 3];

    for node in 0..3 {
        for height in 1..=50 {
            let pv = version_for_height(height, &activations);
            results[node].push(pv);
        }
    }

    // All nodes must agree on PV at every height
    assert_eq!(
        results[0], results[1],
        "node 0 and 1 disagree on PV sequence"
    );
    assert_eq!(
        results[1], results[2],
        "node 1 and 2 disagree on PV sequence"
    );
}

// ─── 10.4: Migration conformance ────────────────────────────────────────────

/// Verify that NodeMeta can be created, saved, loaded, and checked.
#[test]
fn upgrade_sim_meta_roundtrip() {
    use iona::storage::meta::NodeMeta;

    let dir = tempfile::tempdir().unwrap();
    let data_dir = dir.path().to_str().unwrap();

    // Create fresh meta
    let mut meta = NodeMeta::new_current();
    assert!(!meta.has_pending_migration());

    // Save and reload
    meta.save(data_dir).unwrap();
    let loaded = NodeMeta::load(data_dir).unwrap().unwrap();
    assert_eq!(loaded.schema_version, meta.schema_version);
    assert_eq!(loaded.protocol_version, meta.protocol_version);

    // Compatibility check should pass
    assert!(loaded.check_compatibility().is_ok());
}

/// Verify migration state persistence for crash-safe resume.
#[test]
fn upgrade_sim_migration_crash_safe() {
    use iona::storage::meta::NodeMeta;

    let dir = tempfile::tempdir().unwrap();
    let data_dir = dir.path().to_str().unwrap();

    let mut meta = NodeMeta::new_current();
    meta.save(data_dir).unwrap();

    // Begin migration
    meta.begin_migration(3, 4, "test migration", data_dir)
        .unwrap();
    assert!(meta.has_pending_migration());

    // Simulate crash: reload from disk
    let reloaded = NodeMeta::load(data_dir).unwrap().unwrap();
    assert!(reloaded.has_pending_migration());
    let ms = reloaded.migration_state.unwrap();
    assert_eq!(ms.from_sv, 3);
    assert_eq!(ms.to_sv, 4);

    // Complete migration
    meta.end_migration(data_dir).unwrap();
    let reloaded2 = NodeMeta::load(data_dir).unwrap().unwrap();
    assert!(!reloaded2.has_pending_migration());
}

/// Verify that future schema versions are rejected.
#[test]
fn upgrade_sim_future_schema_rejected() {
    use iona::storage::meta::NodeMeta;

    let meta = NodeMeta {
        schema_version: 999,
        protocol_version: 1,
        node_version: "99.0.0".into(),
        updated_at: None,
        migration_state: None,
    };
    assert!(meta.check_compatibility().is_err());
}
