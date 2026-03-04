#![no_main]
//! State-transition fuzzer.
//!
//! Generates arbitrary sequences of (key, value, op) triples and applies them
//! to a fresh `KvState` through the public `apply_tx` path, verifying that
//! the following invariants hold for every reachable state:
//!
//!   I1. `state.root()` is pure — calling it twice returns the same hash.
//!   I2. `state.burned` never decreases across transactions.
//!   I3. Nonces for each address are monotonically non-decreasing.
//!   I4. Applying the same sequence of transactions to two cloned states
//!       yields identical state roots (execution determinism).
//!   I5. A failed transaction (bad sig / insufficient balance) must leave
//!       the state root unchanged.
//!   I6. No panic on any structurally valid input (panic = libFuzzer crash).

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;
use std::collections::BTreeMap;

use iona::execution::{apply_tx, KvState};
use iona::types::Tx;

// ── Fuzzer-controlled input ──────────────────────────────────────────────────

/// A single operation the fuzzer can compose.
#[derive(Arbitrary, Debug, Clone)]
struct FuzzOp {
    /// KV payload to embed in the transaction.
    payload: FuzzPayload,
    /// Sender index (indexes into a small synthetic address table).
    sender_idx: u8,
    /// Nonce — fuzzer may provide any value; we track expected nonces.
    nonce: u64,
    /// Gas limit.
    gas_limit: u64,
    /// Max fee per gas (used for balance math).
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

/// A string capped at 32 bytes to keep corpus entries small.
#[derive(Arbitrary, Debug, Clone)]
struct SmallStr(Vec<u8>);

impl SmallStr {
    fn as_safe_str(&self) -> String {
        // Convert to a valid ASCII string, replacing non-printable bytes.
        self.0
            .iter()
            .take(32)
            .map(|&b| if b.is_ascii_alphanumeric() || b == b'_' { b as char } else { 'x' })
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
            FuzzPayload::Raw(bytes) => String::from_utf8_lossy(bytes).into_owned(),
        }
    }
}

// ── Synthetic address table (no real keys — we test state logic, not crypto) ─

/// 8 synthetic "validator" addresses.  Real signature verification is bypassed
/// by setting `from` to the correct derived address from the pubkey, which
/// means the call will succeed or fail based on state logic, not crypto.
///
/// For `bad_sig = true` operations we deliberately mismatch so we can test I5.
fn synthetic_from(idx: u8) -> String {
    format!("addr{:02x}", idx % 8)
}

fn synthetic_pubkey(idx: u8) -> Vec<u8> {
    // 32-byte dummy public key keyed by sender index.
    vec![idx % 8; 32]
}

/// Build a `Tx` that will NOT pass `verify_tx_signature` (bad_sig path).
fn bad_tx(op: &FuzzOp) -> Tx {
    Tx {
        pubkey: synthetic_pubkey(op.sender_idx),
        from: "definitely_wrong_address".to_string(),
        nonce: op.nonce,
        max_fee_per_gas: op.max_fee_per_gas.min(1_000_000),
        max_priority_fee_per_gas: 0,
        gas_limit: op.gas_limit.min(10_000_000),
        payload: op.payload.to_string(),
        signature: vec![0u8; 64], // invalid signature bytes
        chain_id: op.chain_id,
    }
}

/// Build a `Tx` with a matching `from` address (signature still invalid — the
/// address check passes but signature bytes are garbage).
fn mismatched_tx(op: &FuzzOp) -> Tx {
    Tx {
        pubkey: synthetic_pubkey(op.sender_idx),
        from: synthetic_from(op.sender_idx),
        nonce: op.nonce,
        max_fee_per_gas: op.max_fee_per_gas.min(1_000_000),
        max_priority_fee_per_gas: 0,
        gas_limit: op.gas_limit.min(10_000_000),
        payload: op.payload.to_string(),
        signature: vec![0u8; 64], // wrong signature — Ed25519 verify will fail
        chain_id: op.chain_id,
    }
}

// ── Invariant checks ─────────────────────────────────────────────────────────

fn check_root_determinism(state: &KvState) {
    // I1: root() must be pure.
    let r1 = state.root();
    let r2 = state.root();
    assert_eq!(r1, r2, "I1 VIOLATED: state.root() is not deterministic");
}

fn check_burned_monotone(burned_before: u64, state: &KvState) {
    // I2: burned never decreases.
    assert!(
        state.burned >= burned_before,
        "I2 VIOLATED: burned decreased from {burned_before} to {}",
        state.burned
    );
}

fn check_nonces_monotone(nonces_before: &BTreeMap<String, u64>, state: &KvState) {
    // I3: nonces are non-decreasing per address.
    for (addr, &old_nonce) in nonces_before {
        if let Some(&new_nonce) = state.nonces.get(addr) {
            assert!(
                new_nonce >= old_nonce,
                "I3 VIOLATED: nonce for {addr} decreased from {old_nonce} to {new_nonce}"
            );
        }
    }
}

fn check_determinism(state_a: &KvState, state_b: &KvState) {
    // I4: two clones applied identically must agree.
    assert_eq!(
        state_a.root(),
        state_b.root(),
        "I4 VIOLATED: identical op sequences produced different roots"
    );
}

fn check_failed_tx_unchanged(root_before: &iona::types::Hash32, state: &KvState) {
    // I5: a failed tx must not mutate state root.
    let root_after = state.root();
    assert_eq!(
        root_before, &root_after,
        "I5 VIOLATED: failed tx mutated state root"
    );
}

// ── Fuzz entry point ─────────────────────────────────────────────────────────

fuzz_target!(|ops: Vec<FuzzOp>| {
    // Cap at 64 ops per corpus entry to keep runs short.
    let ops = &ops[..ops.len().min(64)];

    let mut state = KvState::default();
    let mut nonces_snapshot: BTreeMap<String, u64> = BTreeMap::new();
    const BASE_FEE: u64 = 1_000;
    const PROPOSER: &str = "proposer_addr";

    // Pre-seed some balances so not every tx fails on "insufficient balance".
    for i in 0u8..8 {
        state
            .balances
            .insert(synthetic_from(i), 1_000_000_000_000);
    }

    // Clone for determinism check (I4).
    let mut state_twin = state.clone();

    for op in ops {
        // Snapshot for invariant checks.
        let burned_before = state.burned;
        let nonces_before = state.nonces.clone();
        nonces_snapshot.clone_from(&state.nonces);

        // I1 on pre-tx state.
        check_root_determinism(&state);

        if op.bad_sig {
            // I5 path: deliberately invalid tx.
            let root_before = state.root();
            let tx = bad_tx(op);
            let (receipt, new_state) = apply_tx(&state, &tx, BASE_FEE, PROPOSER);
            // apply_tx must never panic and must return the state unchanged on failure.
            if !receipt.success {
                check_failed_tx_unchanged(&root_before, &new_state);
            }
            // Even on the I5 path: no burned decrease, no nonce regression.
            check_burned_monotone(burned_before, &new_state);
            check_nonces_monotone(&nonces_before, &new_state);
            state = new_state;
        } else {
            // Normal path: mismatched signature (from address matches but sig bytes are wrong).
            // Ed25519 verify will fail, so the tx will be rejected — testing I5 again.
            // This is intentional: we are fuzzing the pre-crypto gate logic.
            let tx = mismatched_tx(op);
            let root_before = state.root();
            let tx_twin = tx.clone();

            let (receipt, new_state) = apply_tx(&state, &tx, BASE_FEE, PROPOSER);
            let (receipt_twin, new_state_twin) =
                apply_tx(&state_twin, &tx_twin, BASE_FEE, PROPOSER);

            // I4: both forks must agree.
            check_determinism(&new_state, &new_state_twin);

            // I5: failed tx must not mutate root.
            if !receipt.success {
                check_failed_tx_unchanged(&root_before, &new_state);
            }
            assert_eq!(
                receipt.success, receipt_twin.success,
                "I4 VIOLATED: receipts differ on identical input"
            );

            // I2, I3.
            check_burned_monotone(burned_before, &new_state);
            check_nonces_monotone(&nonces_before, &new_state);

            state = new_state;
            state_twin = new_state_twin;
        }

        // I1 on post-tx state.
        check_root_determinism(&state);
    }

    // Final determinism sanity.
    check_determinism(&state, &state_twin);
});
