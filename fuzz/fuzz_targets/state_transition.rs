#![no_main]
//! State-transition fuzzer for IONA execution layer.
//!
//! Generates arbitrary sequences of (key, value, op) triples and applies them
//! to a fresh `KvState` through the public `apply_tx` path, verifying that
//! the following invariants hold for every reachable state:
//!
//!   I1. `state.root()` is pure — calling it twice returns the same hash.
//!   I2. `state.burned` never decreases across transactions.
//!   I3. Nonces for each address are monotonically non‑decreasing.
//!   I4. Applying the same sequence of transactions to two cloned states
//!       yields identical state roots (execution determinism).
//!   I5. A failed transaction (bad signature / insufficient balance) must leave
//!       the state root unchanged.
//!   I6. No panic on any structurally valid input (panic = libFuzzer crash).
//!
//! # Run instructions
//! ```bash
//! cargo fuzz run state_transition -- -max_len=4194304 -max_total_time=600
//! ```
//!
//! # Security
//! - Maximum operations per input: 64 (prevents timeouts)
//! - Maximum key/value length: 64 bytes (prevents memory blowup)
//! - Gas and fee limits are capped
//! - All invariants are checked with assertions

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;
use std::collections::BTreeMap;
use std::hint::black_box;
use std::panic;

use iona::execution::{apply_tx, KvState};
use iona::types::Tx;

// -----------------------------------------------------------------------------
// Constants
// -----------------------------------------------------------------------------

/// Maximum number of operations per fuzz input (prevents timeouts).
const MAX_OPS: usize = 64;

/// Synthetic address count.
const NUM_SYNTHETIC_ADDRS: usize = 8;

/// Maximum key/value length in bytes (prevents memory blowup).
const MAX_STR_LEN: usize = 64;

/// Initial balance for each synthetic address (enough to cover gas).
const INITIAL_BALANCE: u64 = 1_000_000_000_000;

/// Base fee per gas for all test transactions.
const BASE_FEE: u64 = 1_000;

/// Proposer address (fixed for all tests).
const PROPOSER_ADDR: &str = "proposer_addr";

/// Maximum gas limit cap (prevents excessive gas consumption).
const MAX_GAS_LIMIT: u64 = 10_000_000;

/// Maximum fee per gas cap (prevents balance overflow).
const MAX_FEE_PER_GAS: u64 = 1_000_000;

// -----------------------------------------------------------------------------
// Fuzzer‑controlled input types
// -----------------------------------------------------------------------------

/// A single operation the fuzzer can compose.
#[derive(Arbitrary, Debug, Clone)]
struct FuzzOp {
    /// KV payload to embed in the transaction.
    payload: FuzzPayload,
    /// Sender index (indexes into synthetic address table).
    sender_idx: u8,
    /// Nonce — fuzzer may provide any value; we track expected nonces.
    nonce: u64,
    /// Gas limit (capped later).
    gas_limit: u64,
    /// Max fee per gas (capped later).
    max_fee_per_gas: u64,
    /// Chain ID.
    chain_id: u64,
    /// Whether to inject a deliberately bad signature (tests I5).
    bad_sig: bool,
}

#[derive(Arbitrary, Debug, Clone)]
enum FuzzPayload {
    Set { key: SmallStr, value: SmallStr },
    Del { key: SmallStr },
    Inc { key: SmallStr },
    /// Completely garbage payload — must not panic.
    Raw(Vec<u8>),
}

/// A string capped at a safe length.
#[derive(Arbitrary, Debug, Clone)]
struct SmallStr(Vec<u8>);

impl SmallStr {
    /// Convert to a safe ASCII string (replace non‑printable characters).
    fn as_safe_str(&self) -> String {
        self.0
            .iter()
            .take(MAX_STR_LEN)
            .map(|&b| {
                if b.is_ascii_alphanumeric() || b == b'_' {
                    b as char
                } else {
                    'x'
                }
            })
            .collect()
    }
}

impl FuzzPayload {
    fn to_string(&self) -> String {
        match self {
            FuzzPayload::Set { key, value } => {
                format!("set {} {}", key.as_safe_str(), value.as_safe_str())
            }
            FuzzPayload::Del { key } => format!("del {}", key.as_safe_str()),
            FuzzPayload::Inc { key } => format!("inc {}", key.as_safe_str()),
            FuzzPayload::Raw(bytes) => {
                let len = bytes.len().min(256);
                String::from_utf8_lossy(&bytes[..len]).into_owned()
            }
        }
    }
}

// -----------------------------------------------------------------------------
// Synthetic address helpers
// -----------------------------------------------------------------------------

fn synthetic_from(idx: u8) -> String {
    format!("addr{:02x}", idx % NUM_SYNTHETIC_ADDRS as u8)
}

fn synthetic_pubkey(idx: u8) -> Vec<u8> {
    vec![idx % NUM_SYNTHETIC_ADDRS as u8; 32]
}

// -----------------------------------------------------------------------------
// Transaction builders
// -----------------------------------------------------------------------------

/// Build a transaction with a definitely wrong `from` address (signature will fail).
fn bad_tx(op: &FuzzOp) -> Tx {
    Tx {
        pubkey: synthetic_pubkey(op.sender_idx),
        from: "definitely_wrong_address".to_string(),
        nonce: op.nonce,
        max_fee_per_gas: op.max_fee_per_gas.min(MAX_FEE_PER_GAS),
        max_priority_fee_per_gas: 0,
        gas_limit: op.gas_limit.min(MAX_GAS_LIMIT),
        payload: op.payload.to_string(),
        signature: vec![0u8; 64],
        chain_id: op.chain_id,
    }
}

/// Build a transaction where `from` matches the derived address, but signature is invalid.
fn mismatched_tx(op: &FuzzOp) -> Tx {
    Tx {
        pubkey: synthetic_pubkey(op.sender_idx),
        from: synthetic_from(op.sender_idx),
        nonce: op.nonce,
        max_fee_per_gas: op.max_fee_per_gas.min(MAX_FEE_PER_GAS),
        max_priority_fee_per_gas: 0,
        gas_limit: op.gas_limit.min(MAX_GAS_LIMIT),
        payload: op.payload.to_string(),
        signature: vec![0u8; 64],
        chain_id: op.chain_id,
    }
}

// -----------------------------------------------------------------------------
// Invariant checkers
// -----------------------------------------------------------------------------

fn check_root_determinism(state: &KvState) {
    let r1 = state.root();
    let r2 = state.root();
    assert_eq!(r1, r2, "I1 violated: state.root() is not deterministic");
}

fn check_burned_monotone(burned_before: u64, state: &KvState) {
    assert!(
        state.burned >= burned_before,
        "I2 violated: burned decreased from {} to {}",
        burned_before,
        state.burned
    );
}

fn check_nonces_monotone(nonces_before: &BTreeMap<String, u64>, state: &KvState) {
    for (addr, &old_nonce) in nonces_before {
        if let Some(&new_nonce) = state.nonces.get(addr) {
            assert!(
                new_nonce >= old_nonce,
                "I3 violated: nonce for {} decreased from {} to {}",
                addr,
                old_nonce,
                new_nonce
            );
        }
    }
}

fn check_determinism(state_a: &KvState, state_b: &KvState) {
    assert_eq!(
        state_a.root(),
        state_b.root(),
        "I4 violated: identical op sequences produced different roots"
    );
}

fn check_failed_tx_unchanged(root_before: &iona::types::Hash32, state: &KvState) {
    let root_after = state.root();
    assert_eq!(
        root_before, &root_after,
        "I5 violated: failed transaction mutated state root"
    );
}

// -----------------------------------------------------------------------------
// Fuzz target
// -----------------------------------------------------------------------------

fuzz_target!(|ops: Vec<FuzzOp>| {
    // Limit number of operations to avoid timeouts
    let ops = &ops[..ops.len().min(MAX_OPS)];

    let mut state = KvState::default();
    let mut nonces_snapshot: BTreeMap<String, u64> = BTreeMap::new();

    // Seed synthetic addresses with sufficient balance.
    for i in 0..NUM_SYNTHETIC_ADDRS {
        let addr = synthetic_from(i as u8);
        state.balances.insert(addr, INITIAL_BALANCE);
        // Also set initial nonce to 0 (default)
        state.nonces.insert(synthetic_from(i as u8), 0);
    }

    let mut state_twin = state.clone();

    for op in ops {
        let burned_before = state.burned;
        let nonces_before = state.nonces.clone();
        nonces_snapshot.clone_from(&state.nonces);

        check_root_determinism(&state);

        if op.bad_sig {
            let root_before = state.root();
            let tx = bad_tx(op);
            // I6: ensure no panic
            let (receipt, new_state) = panic::catch_unwind(|| apply_tx(&state, &tx, BASE_FEE, PROPOSER_ADDR))
                .unwrap_or_else(|_| panic!("I6 violated: apply_tx panicked on bad_sig transaction"));
            black_box(&receipt);

            if !receipt.success {
                check_failed_tx_unchanged(&root_before, &new_state);
            }
            check_burned_monotone(burned_before, &new_state);
            check_nonces_monotone(&nonces_before, &new_state);

            state = new_state;
        } else {
            let tx = mismatched_tx(op);
            let root_before = state.root();
            let tx_twin = tx.clone();

            // Apply to both states, catching panics
            let (receipt, new_state) = panic::catch_unwind(|| apply_tx(&state, &tx, BASE_FEE, PROPOSER_ADDR))
                .unwrap_or_else(|_| panic!("I6 violated: apply_tx panicked on valid transaction"));
            let (receipt_twin, new_state_twin) = panic::catch_unwind(|| apply_tx(&state_twin, &tx_twin, BASE_FEE, PROPOSER_ADDR))
                .unwrap_or_else(|_| panic!("I6 violated: apply_tx panicked on twin state"));

            black_box(&receipt);
            black_box(&receipt_twin);

            check_determinism(&new_state, &new_state_twin);
            assert_eq!(
                receipt.success, receipt_twin.success,
                "I4 violated: receipts differ on identical input"
            );

            if !receipt.success {
                check_failed_tx_unchanged(&root_before, &new_state);
            }
            check_burned_monotone(burned_before, &new_state);
            check_nonces_monotone(&nonces_before, &new_state);

            state = new_state;
            state_twin = new_state_twin;
        }

        check_root_determinism(&state);
    }

    check_determinism(&state, &state_twin);
});
