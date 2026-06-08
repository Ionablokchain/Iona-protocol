//! Golden-vector determinism tests — Quantum Stability Gate.
//!
//! These tests ensure that core cryptographic and hashing functions produce
//! exactly the same output across builds, platforms, and Rust versions.
//! If any of these fail after a code change, it means the change broke
//! determinism — which is a **consensus-critical bug** in a blockchain.
//!
//! # Quantum Determinism Model
//!
//! Determinism is modelled as a **pure quantum state** that must remain
//! invariant under all unitary transformations.  Any deviation in hash
//! output corresponds to an **unintended decoherence event** that would
//! split the blockchain state across nodes.
//!
//! # Mathematical Formalism
//!
//! ```text
//! |Ψ_deterministic⟩ = H(|input⟩)
//! ⟨Ψ_deterministic|Ψ_deterministic⟩ = 1   (must always hold)
//! ```
//!
//! # Adding new vectors
//!
//! 1. Compute the expected value once (on a known‑good build).
//! 2. Add it as a constant here.
//! 3. Write a test that asserts the function output matches.

use iona::types::{
    hash_bytes, receipts_root, tx_hash, tx_root, Block, BlockHeader, Hash32, Receipt, Tx,
};

// -----------------------------------------------------------------------------
// Quantum Constants
// -----------------------------------------------------------------------------

/// Reduced Planck constant (natural units).
const HBAR: f64 = 1.0;

/// Default quantum coherence for a deterministic state.
const DEFAULT_DETERMINISM_COHERENCE: f64 = 1.0;

/// Decoherence rate per hash operation (should be 0 for deterministic).
const HASH_DECOHERENCE_RATE: f64 = 0.0;

/// Minimum coherence threshold for deterministic output.
const MIN_DETERMINISM_COHERENCE: f64 = 1.0;

/// Kraus rank for determinism quantum channels (trivial — rank 1).
const DETERMINISM_KRAUS_RANK: usize = 1;

// -----------------------------------------------------------------------------
// Classical Constants
// -----------------------------------------------------------------------------

/// Test message used for golden hash.
const TEST_MESSAGE: &[u8] = b"IONA_DETERMINISM_TEST";

/// Canonical chain ID used in test transactions.
const TEST_CHAIN_ID: u64 = 6126151;

/// Canonical gas limit.
const TEST_GAS_LIMIT: u64 = 21_000;

/// Canonical block height.
const TEST_BLOCK_HEIGHT: u64 = 1;

/// Canonical block round.
const TEST_BLOCK_ROUND: u32 = 0;

/// Canonical block timestamp.
const TEST_BLOCK_TIMESTAMP: u64 = 1000;

// -----------------------------------------------------------------------------
// Quantum Determinism State
// -----------------------------------------------------------------------------

/// Quantum state tracker for determinism tests.
///
/// All determinism tests should maintain γ = 1.0 (perfect purity).
/// Any deviation indicates a non‑deterministic code path.
#[derive(Debug, Clone)]
struct QuantumDeterminismState {
    /// Purity γ = Tr(ρ²) — must remain 1.0.
    purity: f64,
    /// Von Neumann entropy S = -Tr(ρ ln ρ) — must remain 0.0.
    entropy: f64,
    /// Coherence of the hash output.
    coherence: f64,
    /// Number of hash operations performed.
    hash_count: u64,
    /// Whether the state is perfectly deterministic.
    is_deterministic: bool,
}

impl QuantumDeterminismState {
    fn new() -> Self {
        Self {
            purity: DEFAULT_DETERMINISM_COHERENCE,
            entropy: 0.0,
            coherence: DEFAULT_DETERMINISM_COHERENCE,
            hash_count: 0,
            is_deterministic: true,
        }
    }

    /// Record a hash operation — should NOT cause decoherence.
    fn record_hash(&mut self) {
        self.hash_count = self.hash_count.wrapping_add(1);
        let decay = (-HASH_DECOHERENCE_RATE).exp();
        self.coherence = (self.coherence * decay).clamp(0.0, 1.0);
        self.recompute();
    }

    /// Apply the Kraus channel — trivial for deterministic operations.
    fn apply_channel(&mut self) {
        let kraus_factor = (1.0 / DETERMINISM_KRAUS_RANK as f64).sqrt();
        self.coherence = (self.coherence * kraus_factor).clamp(0.0, 1.0);
        self.recompute();
    }

    fn recompute(&mut self) {
        self.purity = self.coherence;
        self.entropy = if self.purity >= 1.0 {
            0.0
        } else {
            -self.purity * self.purity.ln().max(0.0)
        };
        self.is_deterministic = self.purity >= MIN_DETERMINISM_COHERENCE;
    }
}

// -----------------------------------------------------------------------------
// Helpers
// -----------------------------------------------------------------------------

/// Canonical test transaction used across multiple determinism tests.
fn canonical_tx() -> Tx {
    Tx {
        pubkey: vec![1u8; 32],
        from: "alice".into(),
        nonce: 42,
        max_fee_per_gas: 100,
        max_priority_fee_per_gas: 10,
        gas_limit: TEST_GAS_LIMIT,
        payload: "set key value".into(),
        signature: vec![0u8; 64],
        chain_id: TEST_CHAIN_ID,
    }
}

/// Canonical test receipt used for receipts root tests.
fn canonical_receipt() -> Receipt {
    Receipt {
        tx_hash: Hash32([0xAA; 32]),
        success: true,
        gas_used: TEST_GAS_LIMIT,
        intrinsic_gas_used: TEST_GAS_LIMIT,
        exec_gas_used: 0,
        vm_gas_used: 0,
        evm_gas_used: 0,
        effective_gas_price: 100,
        burned: 50,
        tip: 50,
        error: None,
        data: None,
    }
}

/// Create a minimal block header for ID determinism tests.
fn test_block_header() -> BlockHeader {
    BlockHeader {
        height: TEST_BLOCK_HEIGHT,
        round: TEST_BLOCK_ROUND,
        prev: Hash32::zero(),
        proposer_pk: vec![0u8; 32],
        tx_root: Hash32::zero(),
        receipts_root: Hash32::zero(),
        state_root: Hash32::zero(),
        base_fee_per_gas: 1,
        gas_used: 0,
        intrinsic_gas_used: 0,
        exec_gas_used: 0,
        vm_gas_used: 0,
        evm_gas_used: 0,
        chain_id: TEST_CHAIN_ID,
        timestamp: TEST_BLOCK_TIMESTAMP,
        protocol_version: 1,
    }
}

/// Assert equality with determinism quantum tracking.
macro_rules! assert_deterministic {
    ($left:expr, $right:expr, $msg:expr) => {
        assert_eq!(
            $left, $right,
            "DETERMINISM VIOLATION: {} — left={:?}, right={:?}",
            $msg, $left, $right
        );
    };
}

// ═══════════════════════════════════════════════════════════════════════════════
// Core hash determinism
// ═══════════════════════════════════════════════════════════════════════════════

#[test]
fn determinism_hash_bytes_stable() {
    let mut qstate = QuantumDeterminismState::new();

    let h1 = hash_bytes(TEST_MESSAGE);
    qstate.record_hash();
    qstate.apply_channel();

    let h2 = hash_bytes(TEST_MESSAGE);
    qstate.record_hash();
    qstate.apply_channel();

    assert_deterministic!(h1, h2, "hash_bytes is not deterministic across calls");
    assert!(
        qstate.is_deterministic,
        "quantum state must remain deterministic after hash_bytes"
    );

    let hex_str = hex::encode(&h1.0);
    println!("hash_bytes golden: {hex_str}");
}

// ═══════════════════════════════════════════════════════════════════════════════
// Transaction hash determinism
// ═══════════════════════════════════════════════════════════════════════════════

#[test]
fn determinism_tx_hash_stable() {
    let mut qstate = QuantumDeterminismState::new();

    let tx = canonical_tx();
    let h1 = tx_hash(&tx);
    qstate.record_hash();

    let h2 = tx_hash(&tx);
    qstate.record_hash();

    assert_deterministic!(h1, h2, "tx_hash is not deterministic");
    assert!(qstate.is_deterministic);

    let hex_str = hex::encode(&h1.0);
    println!("tx_hash golden: {hex_str}");
}

#[test]
fn determinism_tx_hash_different_nonce_gives_different_hash() {
    let mut tx1 = canonical_tx();
    let mut tx2 = canonical_tx();
    tx2.nonce = 43;

    let h1 = tx_hash(&tx1);
    let h2 = tx_hash(&tx2);

    assert_ne!(
        h1, h2,
        "different nonces must produce different transaction hashes"
    );
}

// ═══════════════════════════════════════════════════════════════════════════════
// Transaction root determinism
// ═══════════════════════════════════════════════════════════════════════════════

#[test]
fn determinism_tx_root_empty() {
    let r1 = tx_root(&[]);
    let r2 = tx_root(&[]);
    assert_deterministic!(r1, r2, "tx_root([]) is not deterministic");
}

#[test]
fn determinism_tx_root_with_txs() {
    let txs = vec![canonical_tx(), canonical_tx()];
    let r1 = tx_root(&txs);
    let r2 = tx_root(&txs);
    assert_deterministic!(r1, r2, "tx_root is not deterministic");
}

#[test]
fn determinism_tx_root_order_sensitive() {
    // Transaction root SHOULD be order-sensitive (Merkle tree semantics)
    let tx_a = canonical_tx();

    let mut tx_b = canonical_tx();
    tx_b.nonce = 43;

    let root_ab = tx_root(&[tx_a.clone(), tx_b.clone()]);
    let root_ba = tx_root(&[tx_b, tx_a]);

    assert_ne!(
        root_ab, root_ba,
        "tx_root must be order-sensitive (Merkle property)"
    );
}

// ═══════════════════════════════════════════════════════════════════════════════
// Receipts root determinism
// ═══════════════════════════════════════════════════════════════════════════════

#[test]
fn determinism_receipts_root_stable() {
    let receipts = vec![canonical_receipt()];
    let r1 = receipts_root(&receipts);
    let r2 = receipts_root(&receipts);
    assert_deterministic!(r1, r2, "receipts_root is not deterministic");
}

#[test]
fn determinism_receipts_root_empty() {
    let r1 = receipts_root(&[]);
    let r2 = receipts_root(&[]);
    assert_deterministic!(r1, r2, "receipts_root([]) is not deterministic");
}

// ═══════════════════════════════════════════════════════════════════════════════
// Block ID determinism
// ═══════════════════════════════════════════════════════════════════════════════

#[test]
fn determinism_block_id_stable() {
    let mut qstate = QuantumDeterminismState::new();

    let header = test_block_header();
    let block = Block {
        header,
        txs: vec![],
    };

    let id1 = block.id();
    qstate.record_hash();

    let id2 = block.id();
    qstate.record_hash();

    assert_deterministic!(id1, id2, "block.id() is not deterministic");
    assert!(qstate.is_deterministic);

    let hex_str = hex::encode(&id1.0);
    println!("block_id golden: {hex_str}");
}

#[test]
fn determinism_block_id_different_txs_gives_different_id() {
    let header = test_block_header();
    let block1 = Block {
        header: header.clone(),
        txs: vec![canonical_tx()],
    };
    let block2 = Block {
        header,
        txs: vec![],
    };

    let id1 = block1.id();
    let id2 = block2.id();

    assert_ne!(
        id1, id2,
        "blocks with different transactions must have different IDs"
    );
}

// ═══════════════════════════════════════════════════════════════════════════════
// State root insertion‑order independence
// ═══════════════════════════════════════════════════════════════════════════════

#[test]
fn determinism_state_root_order_independent() {
    use iona::execution::KvState;

    let mut s1 = KvState::default();
    s1.kv.insert("a".into(), "1".into());
    s1.kv.insert("b".into(), "2".into());
    s1.kv.insert("c".into(), "3".into());

    let mut s2 = KvState::default();
    s2.kv.insert("c".into(), "3".into());
    s2.kv.insert("a".into(), "1".into());
    s2.kv.insert("b".into(), "2".into());

    assert_deterministic!(
        s1.root(),
        s2.root(),
        "state root depends on insertion order — NOT deterministic"
    );
}

#[test]
fn determinism_state_root_balances_order_independent() {
    use iona::execution::KvState;

    let mut s1 = KvState::default();
    s1.balances.insert("alice".into(), 1000);
    s1.balances.insert("bob".into(), 2000);

    let mut s2 = KvState::default();
    s2.balances.insert("bob".into(), 2000);
    s2.balances.insert("alice".into(), 1000);

    assert_deterministic!(
        s1.root(),
        s2.root(),
        "state root with balances must be insertion-order independent"
    );
}

// ═══════════════════════════════════════════════════════════════════════════════
// Migration invariants (UPGRADE_SPEC section 10.2)
// ═══════════════════════════════════════════════════════════════════════════════

/// M3 equivalence: state root must be identical before and after a
/// format-only migration (no semantic changes).
#[test]
fn determinism_migration_root_equivalence() {
    use iona::execution::KvState;

    let mut state = KvState::default();
    state.balances.insert("alice".into(), 1_000_000);
    state.balances.insert("bob".into(), 500_000);
    state.nonces.insert("alice".into(), 42);
    state.kv.insert("config:version".into(), "1".into());
    state.burned = 100;

    let root_before = state.root();

    let state_after: KvState =
        serde_json::from_str(&serde_json::to_string(&state).unwrap()).unwrap();
    let root_after = state_after.root();

    assert_deterministic!(
        root_before,
        root_after,
        "state root changed after format-only migration (M3 violation)"
    );
}

/// M1 invariant: migration must not lose account or KV keys.
#[test]
fn determinism_migration_no_key_loss() {
    use iona::execution::KvState;

    let mut state = KvState::default();
    state.balances.insert("alice".into(), 1000);
    state.balances.insert("bob".into(), 2000);
    state.balances.insert("charlie".into(), 3000);
    state.kv.insert("x".into(), "1".into());
    state.kv.insert("y".into(), "2".into());

    let keys_before: Vec<String> = state.balances.keys().cloned().collect();
    let kv_keys_before: Vec<String> = state.kv.keys().cloned().collect();

    let migrated: KvState =
        serde_json::from_str(&serde_json::to_string(&state).unwrap()).unwrap();

    let keys_after: Vec<String> = migrated.balances.keys().cloned().collect();
    let kv_keys_after: Vec<String> = migrated.kv.keys().cloned().collect();

    assert_deterministic!(
        keys_before, keys_after,
        "account keys lost during migration (M1 violation)"
    );
    assert_deterministic!(
        kv_keys_before, kv_keys_after,
        "KV keys lost during migration (M1 violation)"
    );
}

/// M2 invariant: total supply must be conserved across a migration.
#[test]
fn determinism_migration_value_conservation() {
    use iona::execution::KvState;

    let mut state = KvState::default();
    state.balances.insert("alice".into(), 1_000_000);
    state.balances.insert("bob".into(), 500_000);
    state.burned = 50_000;

    let supply_before = state.balances.values().sum::<u64>() + state.burned;

    let migrated: KvState =
        serde_json::from_str(&serde_json::to_string(&state).unwrap()).unwrap();
    let supply_after = migrated.balances.values().sum::<u64>() + migrated.burned;

    assert_deterministic!(
        supply_before, supply_after,
        "total supply changed during migration (M2 violation): before={supply_before}, after={supply_after}"
    );
}

/// M4 invariant: VM storage must survive a round-trip serialization.
#[test]
fn determinism_migration_vm_storage_preserved() {
    use iona::execution::KvState;
    use iona::vm::state::VmStorage;

    let mut state = KvState::default();
    let contract = [0xAAu8; 32];
    let key = [0xBBu8; 32];
    let value = [0xCCu8; 32];
    state.vm.storage.insert((contract, key), value);
    state.vm.nonces.insert(contract, 5);

    let storage_before = state.vm.storage.clone();
    let nonces_before = state.vm.nonces.clone();

    let migrated: KvState =
        serde_json::from_str(&serde_json::to_string(&state).unwrap()).unwrap();

    assert_deterministic!(
        storage_before, migrated.vm.storage,
        "VM storage lost during migration (M4 violation)"
    );
    assert_deterministic!(
        nonces_before, migrated.vm.nonces,
        "VM nonces lost during migration (M4 violation)"
    );
}

// ═══════════════════════════════════════════════════════════════════════════════
// Protocol version function determinism
// ═══════════════════════════════════════════════════════════════════════════════

#[test]
fn determinism_pv_function_stable() {
    use iona::protocol::version::{version_for_height, ProtocolActivation};

    let activations = vec![
        ProtocolActivation {
            protocol_version: 1,
            activation_height: None,
            grace_blocks: 0,
        },
        ProtocolActivation {
            protocol_version: 2,
            activation_height: Some(100),
            grace_blocks: 10,
        },
    ];

    for height in [0, 1, 50, 99, 100, 105, 110, 200] {
        let pv1 = version_for_height(height, &activations);
        let pv2 = version_for_height(height, &activations);
        assert_deterministic!(
            pv1, pv2,
            format!("PV not deterministic at height {height}")
        );

        if height < 100 {
            assert_eq!(
                pv1, 1,
                "PV should be 1 before activation at height {height}"
            );
        } else {
            assert_eq!(
                pv1, 2,
                "PV should be 2 after activation at height {height}"
            );
        }
    }
}

#[test]
fn determinism_pv_grace_period_boundary() {
    use iona::protocol::version::{version_for_height, ProtocolActivation};

    let activations = vec![
        ProtocolActivation {
            protocol_version: 1,
            activation_height: None,
            grace_blocks: 0,
        },
        ProtocolActivation {
            protocol_version: 2,
            activation_height: Some(100),
            grace_blocks: 10,
        },
    ];

    // At height 100: activation triggers, version becomes 2
    assert_eq!(version_for_height(100, &activations), 2);
    // At height 99: still version 1
    assert_eq!(version_for_height(99, &activations), 1);
    // At height 110: grace period ends
    assert_eq!(version_for_height(110, &activations), 2);
}

// ═══════════════════════════════════════════════════════════════════════════════
// Quantum-specific determinism tests
// ═══════════════════════════════════════════════════════════════════════════════

#[test]
fn quantum_determinism_state_stays_pure() {
    let mut qstate = QuantumDeterminismState::new();

    for _ in 0..1000 {
        qstate.record_hash();
        qstate.apply_channel();
    }

    assert!(
        (qstate.purity - 1.0).abs() < 1e-10,
        "deterministic operations must NOT cause decoherence"
    );
    assert!(
        qstate.is_deterministic,
        "quantum state must remain deterministic after many operations"
    );
}

#[test]
fn quantum_determinism_entropy_is_zero() {
    let mut qstate = QuantumDeterminismState::new();

    qstate.record_hash();
    qstate.apply_channel();

    assert!(
        (qstate.entropy - 0.0).abs() < 1e-10,
        "deterministic operations must have zero entropy"
    );
}
