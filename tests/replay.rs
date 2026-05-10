//! Replay test: execute a chain of blocks from a snapshot and verify state roots.
//!
//! This tests that block execution is fully deterministic and that replaying
//! the same sequence of transactions from the same initial state produces
//! identical state roots every time.

use iona::crypto::ed25519::Ed25519Keypair;
use iona::crypto::tx::{derive_address, tx_sign_bytes};
use iona::crypto::Signer;
use iona::execution::{execute_block, KvState};
use iona::types::{receipts_root, tx_root, Block, BlockHeader, Hash32, Tx};

// -----------------------------------------------------------------------------
// Constants
// -----------------------------------------------------------------------------

/// Number of test accounts (seeds 1..=NUM_ACCOUNTS).
const NUM_ACCOUNTS: u64 = 5;

/// Number of senders per block (seeds 1..=NUM_SENDERS_PER_BLOCK).
const NUM_SENDERS_PER_BLOCK: u64 = 3;

/// Number of blocks in the test chain.
const NUM_BLOCKS: usize = 20;

/// Number of blocks to skip for snapshot replay (first 10, then replay 11..20).
const SNAPSHOT_SKIP_BLOCKS: usize = 10;

/// Number of empty blocks to test.
const NUM_EMPTY_BLOCKS: usize = 5;

/// Number of blocks for receipt determinism test.
const NUM_RECEIPT_BLOCKS: usize = 10;

/// Number of blocks for serialisation roundtrip test.
const NUM_SERIALIZATION_BLOCKS: usize = 5;

/// Chain ID used in test transactions.
const TEST_CHAIN_ID: u64 = 1;

/// Gas limit per transaction.
const TEST_GAS_LIMIT: u64 = 100_000;

/// Max fee per gas for test transactions.
const TEST_MAX_FEE: u64 = 10;

/// Max priority fee per gas for test transactions.
const TEST_MAX_PRIORITY_FEE: u64 = 1;

/// Base fee per gas used in block execution.
const BASE_FEE_PER_GAS: u64 = 1;

/// Proposer address for block building (placeholder).
const PROPOSER_ADDR: &str = "proposer_addr";

/// Initial funding amount for each test account.
const INITIAL_BALANCE: u64 = 10_000_000;

// -----------------------------------------------------------------------------
// Helpers
// -----------------------------------------------------------------------------

/// Create a keypair, its public key bytes, and derived address from a seed.
fn make_keypair(seed: u64) -> (Ed25519Keypair, Vec<u8>, String) {
    let mut seed_bytes = [0u8; 32];
    seed_bytes[..8].copy_from_slice(&seed.to_le_bytes());
    let signer = Ed25519Keypair::from_seed(seed_bytes);
    let pubkey = signer.public_key().0;
    let address = derive_address(&pubkey);
    (signer, pubkey, address)
}

/// Create a signed transaction with the given parameters.
fn make_signed_tx(
    signer: &Ed25519Keypair,
    pubkey: &[u8],
    address: &str,
    nonce: u64,
    payload: &str,
) -> Tx {
    let mut tx = Tx {
        from: address.to_string(),
        nonce,
        payload: payload.to_string(),
        pubkey: pubkey.to_vec(),
        signature: vec![],
        gas_limit: TEST_GAS_LIMIT,
        max_fee_per_gas: TEST_MAX_FEE,
        max_priority_fee_per_gas: TEST_MAX_PRIORITY_FEE,
        chain_id: TEST_CHAIN_ID,
    };
    let msg = tx_sign_bytes(&tx);
    tx.signature = signer.sign(&msg).0;
    tx
}

/// Create the genesis state with funded test accounts.
fn genesis_state() -> KvState {
    let mut state = KvState::default();
    for seed in 1..=NUM_ACCOUNTS {
        let (_, _, address) = make_keypair(seed);
        state.balances.insert(address, INITIAL_BALANCE);
    }
    state
}

/// Build a chain of `n` blocks with transactions from multiple senders.
/// Returns `(initial_state, vector of (transactions, expected_state_root))`.
fn build_chain(n: usize) -> (KvState, Vec<(Vec<Tx>, Hash32)>) {
    let initial_state = genesis_state();
    let mut state = initial_state.clone();
    let mut chain = Vec::new();

    for height in 1..=n {
        let mut txs = Vec::new();
        for sender_seed in 1..=NUM_SENDERS_PER_BLOCK {
            let (signer, pubkey, address) = make_keypair(sender_seed);
            // Each sender sends one transaction per block, nonce increases by height.
            let nonce = (height - 1) as u64;
            let payload = format!("set block_{height}_sender_{sender_seed} value_{height}");
            txs.push(make_signed_tx(&signer, &pubkey, &address, nonce, &payload));
        }

        let (new_state, _gas, _receipts) = execute_block(&state, &txs, BASE_FEE_PER_GAS, PROPOSER_ADDR);
        let root = new_state.root();
        chain.push((txs, root));
        state = new_state;
    }

    (initial_state, chain)
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

/// Replay the exact same chain twice and verify all state roots match.
#[test]
fn replay_chain_deterministic() {
    let (initial_state, chain) = build_chain(NUM_BLOCKS);

    let mut state = initial_state;
    for (i, (txs, expected_root)) in chain.iter().enumerate() {
        let (new_state, _gas, _receipts) = execute_block(&state, txs, BASE_FEE_PER_GAS, PROPOSER_ADDR);
        let got_root = new_state.root();
        assert_eq!(
            got_root,
            *expected_root,
            "State root mismatch at height {} on replay",
            i + 1
        );
        state = new_state;
    }
}

/// Replay from a mid‑chain snapshot (simulate crash recovery).
#[test]
fn replay_from_snapshot() {
    let (initial_state, chain) = build_chain(NUM_BLOCKS);

    // Execute first 10 blocks to get snapshot state
    let mut snapshot_state = initial_state;
    for (txs, _) in chain.iter().take(SNAPSHOT_SKIP_BLOCKS) {
        let (new_state, _gas, _receipts) = execute_block(&snapshot_state, txs, BASE_FEE_PER_GAS, PROPOSER_ADDR);
        snapshot_state = new_state;
    }

    // Replay blocks 11..20 from snapshot
    let mut state = snapshot_state;
    for (i, (txs, expected_root)) in chain.iter().skip(SNAPSHOT_SKIP_BLOCKS).enumerate() {
        let (new_state, _gas, _receipts) = execute_block(&state, txs, BASE_FEE_PER_GAS, PROPOSER_ADDR);
        let got_root = new_state.root();
        assert_eq!(
            got_root,
            *expected_root,
            "State root mismatch at height {} on replay from snapshot",
            i + SNAPSHOT_SKIP_BLOCKS + 1
        );
        state = new_state;
    }
}

/// Verify that empty blocks (no transactions) produce deterministic state roots.
#[test]
fn replay_empty_blocks() {
    let state = genesis_state();

    let mut roots = Vec::new();
    let mut current_state = state.clone();
    for _ in 0..NUM_EMPTY_BLOCKS {
        let (new_state, _gas, _receipts) = execute_block(&current_state, &[], BASE_FEE_PER_GAS, PROPOSER_ADDR);
        roots.push(new_state.root());
        current_state = new_state;
    }

    // Replay and compare
    let mut replay_state = state;
    for (i, expected) in roots.iter().enumerate() {
        let (new_state, _gas, _receipts) = execute_block(&replay_state, &[], BASE_FEE_PER_GAS, PROPOSER_ADDR);
        assert_eq!(
            new_state.root(),
            *expected,
            "Empty block root mismatch at height {}",
            i
        );
        replay_state = new_state;
    }
}

/// Verify receipts are deterministic across replays.
#[test]
fn replay_receipts_deterministic() {
    let (initial_state, chain) = build_chain(NUM_RECEIPT_BLOCKS);

    // First pass: collect receipts
    let mut state1 = initial_state.clone();
    let mut all_receipts1 = Vec::new();
    for (txs, _) in &chain {
        let (new_state, _gas, receipts) = execute_block(&state1, txs, BASE_FEE_PER_GAS, PROPOSER_ADDR);
        all_receipts1.push(receipts);
        state1 = new_state;
    }

    // Second pass: verify receipts match
    let mut state2 = initial_state;
    for (i, (txs, _)) in chain.iter().enumerate() {
        let (new_state, _gas, receipts) = execute_block(&state2, txs, BASE_FEE_PER_GAS, PROPOSER_ADDR);
        assert_eq!(
            receipts.len(),
            all_receipts1[i].len(),
            "Receipt count mismatch at height {}",
            i + 1
        );
        for (j, (r1, r2)) in all_receipts1[i].iter().zip(receipts.iter()).enumerate() {
            assert_eq!(
                r1.tx_hash, r2.tx_hash,
                "tx_hash mismatch height={} tx={}",
                i + 1, j
            );
            assert_eq!(
                r1.success, r2.success,
                "success mismatch height={} tx={}",
                i + 1, j
            );
            assert_eq!(
                r1.gas_used, r2.gas_used,
                "gas_used mismatch height={} tx={}",
                i + 1, j
            );
        }
        state2 = new_state;
    }
}

/// Verify state serialisation roundtrip preserves the root.
#[test]
fn replay_state_serialization_roundtrip() {
    let (initial_state, chain) = build_chain(NUM_SERIALIZATION_BLOCKS);

    let mut state = initial_state;
    for (txs, _) in &chain {
        let (new_state, _gas, _receipts) = execute_block(&state, txs, BASE_FEE_PER_GAS, PROPOSER_ADDR);
        let json = serde_json::to_vec(&new_state).expect("serialize");
        let deserialized: KvState = serde_json::from_slice(&json).expect("deserialize");
        assert_eq!(
            new_state.root(),
            deserialized.root(),
            "State root changed after serialisation roundtrip"
        );
        state = new_state;
    }
}
