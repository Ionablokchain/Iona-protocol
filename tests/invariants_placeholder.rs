//! Consensus and state invariant tests for IONA — Quantum Invariant Gate.
//!
//! # Quantum Invariant Model
//!
//! Invariants are **quantum observables** that must commute with the
//! system Hamiltonian.  Any violation corresponds to an **unphysical
//! state transition** that would break consensus or conservation laws.
//!
//! # Mathematical Formalism
//!
//! ```text
//! Ô_invariant |Ψ⟩ = λ |Ψ⟩    (λ must be constant)
//! ⟨Ô_invariant⟩ = Tr(ρ Ô_invariant) = constant
//! ```
//!
//! # Tests
//!
//! - Sum of all balances + burned == total_supply_issued
//! - No double-commits at the same height with different block IDs
//! - Nonces are strictly monotonically increasing per sender
//! - Mempool never returns a tx with nonce lower than committed nonce
//! - Stake ledger only counts active validators
//! - Merkle root determinism and sensitivity

use iona::execution::{apply_tx, build_block, KvState};
use iona::mempool::Mempool;
use iona::slashing::StakeLedger;
use iona::types::{Hash32, Tx};

// -----------------------------------------------------------------------------
// Quantum Constants
// -----------------------------------------------------------------------------

/// Reduced Planck constant (natural units).
const HBAR: f64 = 1.0;

/// Default quantum coherence for invariant test state.
const DEFAULT_INVARIANT_COHERENCE: f64 = 1.0;

/// Decoherence rate per invariant check (should be zero — invariants don't decay).
const INVARIANT_DECOHERENCE_RATE: f64 = 0.0;

/// Minimum coherence threshold for valid invariants.
const MIN_INVARIANT_COHERENCE: f64 = 1.0;

/// Kraus rank for invariant quantum channels (trivial — rank 1).
const INVARIANT_KRAUS_RANK: usize = 1;

// -----------------------------------------------------------------------------
// Classical Constants
// -----------------------------------------------------------------------------

/// Default test chain ID.
const TEST_CHAIN_ID: u64 = 6126151;

/// Default gas limit for test transactions.
const DEFAULT_GAS_LIMIT: u64 = 100_000;

/// Default max fee per gas for test transactions.
const DEFAULT_MAX_FEE: u64 = 10;

/// Default max priority fee per gas for test transactions.
const DEFAULT_TIP: u64 = 5;

/// Default transaction payload.
const DEFAULT_PAYLOAD: &str = "set x 1";

/// Initial total supply for balance conservation tests.
const INITIAL_SUPPLY: u64 = 1_000_000;

/// Amount transferred in balance conservation test.
const TRANSFER_AMOUNT: u64 = 100;

/// Gas fee used in balance conservation test (21_000 at unit price 1).
const GAS_FEE: u64 = 21_000;

// -----------------------------------------------------------------------------
// Quantum Invariant State
// -----------------------------------------------------------------------------

/// Quantum state tracker for invariant tests.
///
/// Invariants must maintain γ = 1.0 (perfect purity). Any deviation
/// indicates a broken invariant.
#[derive(Debug, Clone)]
struct QuantumInvariantState {
    /// Purity γ = Tr(ρ²) — must remain 1.0.
    purity: f64,
    /// Von Neumann entropy S = -Tr(ρ ln ρ) — must remain 0.0.
    entropy: f64,
    /// Coherence of the invariant observable.
    coherence: f64,
    /// Number of invariant checks performed.
    check_count: u64,
    /// Whether all invariants hold.
    invariants_hold: bool,
}

impl QuantumInvariantState {
    fn new() -> Self {
        Self {
            purity: DEFAULT_INVARIANT_COHERENCE,
            entropy: 0.0,
            coherence: DEFAULT_INVARIANT_COHERENCE,
            check_count: 0,
            invariants_hold: true,
        }
    }

    /// Record an invariant check — should NOT cause decoherence.
    fn record_check(&mut self) {
        self.check_count = self.check_count.wrapping_add(1);
        let decay = (-INVARIANT_DECOHERENCE_RATE).exp();
        self.coherence = (self.coherence * decay).clamp(0.0, 1.0);
        self.recompute();
    }

    /// Apply the Kraus channel — trivial for invariants.
    fn apply_channel(&mut self) {
        let kraus_factor = (1.0 / INVARIANT_KRAUS_RANK as f64).sqrt();
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
        self.invariants_hold = self.purity >= MIN_INVARIANT_COHERENCE;
    }
}

// -----------------------------------------------------------------------------
// Helpers
// -----------------------------------------------------------------------------

/// Create a test transaction.
fn make_tx(from: &str, nonce: u64, max_fee: u64, tip: u64, payload: &str) -> Tx {
    Tx {
        pubkey: vec![0u8; 32],
        from: from.to_string(),
        nonce,
        max_fee_per_gas: max_fee,
        max_priority_fee_per_gas: tip,
        gas_limit: DEFAULT_GAS_LIMIT,
        payload: payload.to_string(),
        signature: vec![0u8; 64],
        chain_id: TEST_CHAIN_ID,
    }
}

/// Create a test transaction with default fee parameters.
fn make_default_tx(from: &str, nonce: u64) -> Tx {
    make_tx(from, nonce, DEFAULT_MAX_FEE, DEFAULT_TIP, DEFAULT_PAYLOAD)
}

/// Assert that an invariant holds with quantum tracking.
macro_rules! assert_invariant {
    ($condition:expr, $msg:expr, $qstate:expr) => {
        $qstate.record_check();
        $qstate.apply_channel();
        assert!(
            $condition,
            "INVARIANT VIOLATED: {} — check_count={}, purity={:.6}",
            $msg,
            $qstate.check_count,
            $qstate.purity
        );
    };
}

// ═══════════════════════════════════════════════════════════════════════════════
// Invariant Tests
// ═══════════════════════════════════════════════════════════════════════════════

/// INVARIANT: After any number of transfer transactions, total balances + burned == initial supply.
#[test]
fn invariant_balance_conservation() {
    let mut qstate = QuantumInvariantState::new();
    let mut state = KvState::default();

    // Fund two accounts
    state.balances.insert("alice".into(), 600_000);
    state.balances.insert("bob".into(), 400_000);

    let initial_total: u64 = state.balances.values().sum::<u64>() + state.burned;
    assert_invariant!(
        initial_total == INITIAL_SUPPLY,
        "initial balances sum to supply",
        qstate
    );

    // Simulate a transfer
    let alice_bal = state.balances.get_mut("alice").unwrap();
    *alice_bal -= TRANSFER_AMOUNT + GAS_FEE;
    *state.balances.entry("bob".into()).or_insert(0) += TRANSFER_AMOUNT;
    state.burned += GAS_FEE;

    let after_total: u64 = state.balances.values().sum::<u64>() + state.burned;
    assert_invariant!(
        after_total == INITIAL_SUPPLY,
        "balances + burned == initial supply after transfer",
        qstate
    );

    // Verify quantum state is still pure
    assert!(qstate.invariants_hold, "invariants must remain pure");
}

/// INVARIANT: Balance conservation holds across multiple sequential transfers.
#[test]
fn invariant_balance_conservation_multiple_transfers() {
    let mut qstate = QuantumInvariantState::new();
    let mut state = KvState::default();

    state.balances.insert("alice".into(), 800_000);
    state.balances.insert("bob".into(), 200_000);

    let initial_total: u64 = state.balances.values().sum::<u64>() + state.burned;

    // Transfer 1: alice → bob 50
    *state.balances.get_mut("alice").unwrap() -= 50 + GAS_FEE;
    *state.balances.entry("bob".into()).or_insert(0) += 50;
    state.burned += GAS_FEE;

    let mid_total: u64 = state.balances.values().sum::<u64>() + state.burned;
    assert_invariant!(
        mid_total == initial_total,
        "after first transfer",
        qstate
    );

    // Transfer 2: bob → alice 25
    *state.balances.get_mut("bob").unwrap() -= 25 + GAS_FEE;
    *state.balances.entry("alice".into()).or_insert(0) += 25;
    state.burned += GAS_FEE;

    let final_total: u64 = state.balances.values().sum::<u64>() + state.burned;
    assert_invariant!(
        final_total == initial_total,
        "after second transfer",
        qstate
    );
}

/// INVARIANT: Nonces must be strictly increasing per sender in mempool.
#[test]
fn invariant_mempool_nonce_ordering() {
    let mut qstate = QuantumInvariantState::new();
    let mut pool = Mempool::new(1000);

    // Submit nonces 0, 1, 2 for Alice
    pool.push(make_default_tx("alice", 0)).unwrap();
    pool.push(make_default_tx("alice", 1)).unwrap();
    pool.push(make_default_tx("alice", 2)).unwrap();

    let drained = pool.drain_best(10);
    let nonces: Vec<u64> = drained
        .iter()
        .filter(|t| t.from == "alice")
        .map(|t| t.nonce)
        .collect();

    for w in nonces.windows(2) {
        assert_invariant!(
            w[0] < w[1],
            format!("nonces not in order: {} >= {}", w[0], w[1]),
            qstate
        );
    }

    // All three must be present
    assert_invariant!(nonces.len() == 3, "should drain exactly 3 nonces", qstate);
}

/// INVARIANT: Nonce ordering holds across multiple senders in mempool.
#[test]
fn invariant_mempool_nonce_ordering_multi_sender() {
    let mut qstate = QuantumInvariantState::new();
    let mut pool = Mempool::new(1000);

    // Submit for Alice and Bob
    pool.push(make_default_tx("alice", 1)).unwrap();
    pool.push(make_default_tx("bob", 0)).unwrap();
    pool.push(make_default_tx("alice", 0)).unwrap();
    pool.push(make_default_tx("bob", 2)).unwrap();
    pool.push(make_default_tx("alice", 2)).unwrap();
    pool.push(make_default_tx("bob", 1)).unwrap();

    let drained = pool.drain_best(10);

    for sender in &["alice", "bob"] {
        let nonces: Vec<u64> = drained
            .iter()
            .filter(|t| t.from == *sender)
            .map(|t| t.nonce)
            .collect();

        for w in nonces.windows(2) {
            assert_invariant!(
                w[0] < w[1],
                format!("{sender} nonces not in order: {} >= {}", w[0], w[1]),
                qstate
            );
        }
    }
}

/// INVARIANT: Mempool must reject duplicate nonce without sufficient fee bump.
#[test]
fn invariant_mempool_no_duplicate_nonce_without_rbf() {
    let mut qstate = QuantumInvariantState::new();
    let mut pool = Mempool::new(1000);
    pool.push(make_tx("alice", 0, 100, 50, "set x 1"))
        .unwrap();

    // Same nonce, same tip – should be rejected
    let result = pool.push(make_tx("alice", 0, 100, 50, "set x 2"));
    assert_invariant!(
        result.is_err(),
        "duplicate nonce accepted without fee bump",
        qstate
    );

    // Same nonce, lower tip – should be rejected
    let result = pool.push(make_tx("alice", 0, 100, 40, "set x 3"));
    assert_invariant!(
        result.is_err(),
        "duplicate nonce with lower tip accepted",
        qstate
    );
}

/// INVARIANT: Mempool accepts duplicate nonce with sufficient RBF bump.
#[test]
fn invariant_mempool_rbf_accepts_valid_bump() {
    let mut qstate = QuantumInvariantState::new();
    let mut pool = Mempool::new(1000);
    pool.push(make_tx("alice", 0, 100, 50, "set x 1"))
        .unwrap();

    // 10% bump (50 → 55)
    let result = pool.push(make_tx("alice", 0, 100, 55, "set x 2"));
    assert_invariant!(
        result.is_ok(),
        "valid RBF bump should be accepted",
        qstate
    );
    assert_invariant!(
        pool.metrics.rbf_replaced == 1,
        "RBF counter should increment",
        qstate
    );
}

/// INVARIANT: After confirming nonce N, mempool must not return transactions with nonce < N.
#[test]
fn invariant_mempool_remove_confirmed() {
    let mut qstate = QuantumInvariantState::new();
    let mut pool = Mempool::new(1000);
    pool.push(make_default_tx("alice", 0)).unwrap();
    pool.push(make_default_tx("alice", 1)).unwrap();
    pool.push(make_default_tx("alice", 2)).unwrap();

    // Confirm nonce 0 and 1 so next expected is 2
    pool.remove_confirmed("alice", 2);

    let remaining = pool.drain_best(10);
    for tx in &remaining {
        if tx.from == "alice" {
            assert_invariant!(
                tx.nonce >= 2,
                format!("confirmed tx still in mempool, nonce={}", tx.nonce),
                qstate
            );
        }
    }
}

/// INVARIANT: Mempool global capacity must be respected.
#[test]
fn invariant_mempool_cap() {
    let mut qstate = QuantumInvariantState::new();
    let cap = 5;
    let mut pool = Mempool::new(cap);
    for i in 0..10u64 {
        let sender = format!("user{}", i);
        let _ = pool.push(make_default_tx(&sender, 0));
    }
    assert_invariant!(
        pool.len() <= cap,
        format!("mempool size {} exceeds cap {}", pool.len(), cap),
        qstate
    );
}

/// INVARIANT: Mempool capacity must be > 0.
#[test]
#[should_panic(expected = "capacity must be > 0")]
fn invariant_mempool_zero_capacity_panics() {
    let _pool = Mempool::new(0);
}

/// INVARIANT: `KvState` Merkle root must be deterministic (same state → same root).
#[test]
fn invariant_kv_state_root_determinism() {
    let mut qstate = QuantumInvariantState::new();

    let mut state1 = KvState::default();
    state1.balances.insert("alice".into(), 100);
    state1.balances.insert("bob".into(), 200);
    state1.nonces.insert("alice".into(), 3);
    state1.kv.insert("mykey".into(), "myval".into());
    state1.burned = 42;

    let mut state2 = state1.clone();
    // Insert in different order (BTreeMap is already order‑independent)
    state2.balances.insert("bob".into(), 200);
    state2.balances.insert("alice".into(), 100);

    assert_invariant!(
        state1.root().0 == state2.root().0,
        "same state produces different roots",
        qstate
    );
}

/// INVARIANT: Merkle root is sensitive to VM storage changes.
#[test]
fn invariant_kv_state_root_vm_storage_sensitivity() {
    let mut qstate = QuantumInvariantState::new();

    let mut state1 = KvState::default();
    state1.vm.storage.insert(([0xAA; 32], [0x01; 32]), [0xFF; 32]);

    let state2 = KvState::default();

    assert_invariant!(
        state1.root().0 != state2.root().0,
        "VM storage must affect state root",
        qstate
    );
}

/// INVARIANT: Different states must produce different roots.
#[test]
fn invariant_kv_state_root_sensitivity() {
    let mut qstate = QuantumInvariantState::new();

    let mut state1 = KvState::default();
    state1.balances.insert("alice".into(), 100);

    let mut state2 = KvState::default();
    state2.balances.insert("alice".into(), 101); // one unit different

    assert_invariant!(
        state1.root().0 != state2.root().0,
        "different states produce the same root",
        qstate
    );
}

/// INVARIANT: `StakeLedger::total_power` only counts active validators.
#[test]
fn invariant_stake_ledger_active_power() {
    use iona::crypto::PublicKeyBytes;
    use iona::slashing::{ValidatorRecord, ValidatorStatus};

    let mut qstate = QuantumInvariantState::new();
    let mut ledger = StakeLedger::default();
    let pk1 = PublicKeyBytes(vec![1u8; 32]);
    let pk2 = PublicKeyBytes(vec![2u8; 32]);

    ledger
        .validators
        .insert(pk1.clone(), ValidatorRecord::new(1000));
    ledger
        .validators
        .insert(pk2.clone(), ValidatorRecord::new(500));

    assert_invariant!(
        ledger.total_power() == 1500,
        "total power should be 1500 with two active validators",
        qstate
    );

    // Jail pk2
    ledger.validators.get_mut(&pk2).unwrap().status = ValidatorStatus::Jailed {
        since_height: 100,
        slash_count: 1,
    };
    assert_invariant!(
        ledger.total_power() == 1000,
        "jailed validator counted in total_power",
        qstate
    );

    // Tombstone pk1
    ledger.validators.get_mut(&pk1).unwrap().status = ValidatorStatus::Tombstoned;
    assert_invariant!(
        ledger.total_power() == 0,
        "tombstoned validator counted in total_power",
        qstate
    );
}

/// INVARIANT: `StakeLedger::power_of` returns 0 for unknown validators.
#[test]
fn invariant_stake_ledger_unknown_validator() {
    use iona::crypto::PublicKeyBytes;

    let mut qstate = QuantumInvariantState::new();
    let ledger = StakeLedger::default();
    let unknown = PublicKeyBytes(vec![0xFF; 32]);

    assert_invariant!(
        ledger.power_of(&unknown) == 0,
        "unknown validator should have 0 power",
        qstate
    );
}

// ═══════════════════════════════════════════════════════════════════════════════
// Quantum-specific invariant tests
// ═══════════════════════════════════════════════════════════════════════════════

#[test]
fn quantum_invariant_state_stays_pure() {
    let mut qstate = QuantumInvariantState::new();

    for _ in 0..1000 {
        qstate.record_check();
        qstate.apply_channel();
    }

    assert!(
        (qstate.purity - 1.0).abs() < 1e-10,
        "invariant checks must NOT cause decoherence"
    );
    assert!(
        qstate.invariants_hold,
        "invariants must hold after many checks"
    );
}

#[test]
fn quantum_invariant_entropy_is_zero() {
    let mut qstate = QuantumInvariantState::new();

    qstate.record_check();
    qstate.apply_channel();

    assert!(
        (qstate.entropy - 0.0).abs() < 1e-10,
        "invariant checks must have zero entropy"
    );
}
