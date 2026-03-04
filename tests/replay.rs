//! Replay test: execute a chain of blocks from a snapshot and verify state roots.
//!
//! This tests that block execution is fully deterministic and that replaying
//! the same sequence of transactions from the same initial state produces
//! identical state roots every time.

use iona::execution::{execute_block, KvState};
use iona::types::{Block, BlockHeader, Hash32, Tx, tx_root, receipts_root};
use iona::crypto::ed25519::Ed25519Keypair;
use iona::crypto::Signer;
use iona::crypto::tx::{derive_address, tx_sign_bytes};

// ── Helpers ──────────────────────────────────────────────────────────────

fn make_keypair(seed: u64) -> (Ed25519Keypair, Vec<u8>, String) {
    let mut seed_bytes = [0u8; 32];
    seed_bytes[..8].copy_from_slice(&seed.to_le_bytes());
    let signer = Ed25519Keypair::from_seed(seed_bytes);
    let pk = signer.public_key().0;
    let addr = derive_address(&pk);
    (signer, pk, addr)
}

fn make_signed_tx(signer: &Ed25519Keypair, pk: &[u8], addr: &str, nonce: u64, payload: &str) -> Tx {
    let mut tx = Tx {
        from: addr.to_string(),
        nonce,
        payload: payload.to_string(),
        pubkey: pk.to_vec(),
        signature: vec![],
        gas_limit: 100_000,
        max_fee_per_gas: 10,
        max_priority_fee_per_gas: 1,
        chain_id: 1,
    };
    let msg = tx_sign_bytes(&tx);
    tx.signature = signer.sign(&msg).0;
    tx
}

fn genesis_state() -> KvState {
    let mut state = KvState::default();
    // Fund test accounts
    for seed in 1..=5u64 {
        let (_, _, addr) = make_keypair(seed);
        state.balances.insert(addr, 10_000_000);
    }
    state
}

/// Build a chain of N blocks with transactions.
fn build_chain(n: usize) -> (KvState, Vec<(Vec<Tx>, Hash32)>) {
    let initial = genesis_state();
    let proposer = "proposer_addr".to_string();
    let mut state = initial.clone();
    let mut chain = Vec::new();

    for height in 1..=n {
        // Each block has transactions from different senders
        let mut txs = Vec::new();
        for sender_seed in 1..=3u64 {
            let (signer, pk, addr) = make_keypair(sender_seed);
            let nonce = (height - 1) as u64; // each sender sends 1 tx per block
            let payload = format!("set block_{height}_sender_{sender_seed} value_{height}");
            txs.push(make_signed_tx(&signer, &pk, &addr, nonce, &payload));
        }

        let (new_state, _gas, _receipts) = execute_block(&state, &txs, 1, &proposer);
        let root = new_state.root();
        chain.push((txs, root));
        state = new_state;
    }

    (initial, chain)
}

// ── Tests ────────────────────────────────────────────────────────────────

/// Replay the exact same chain twice and verify all state roots match.
#[test]
fn replay_chain_deterministic() {
    let (initial, chain) = build_chain(20);
    let proposer = "proposer_addr".to_string();

    // Replay
    let mut state = initial.clone();
    for (i, (txs, expected_root)) in chain.iter().enumerate() {
        let (new_state, _gas, _receipts) = execute_block(&state, txs, 1, &proposer);
        let got_root = new_state.root();
        assert_eq!(
            got_root, *expected_root,
            "State root mismatch at height {} on replay",
            i + 1
        );
        state = new_state;
    }
}

/// Replay from a mid-chain snapshot (simulate crash recovery).
#[test]
fn replay_from_snapshot() {
    let (initial, chain) = build_chain(20);
    let proposer = "proposer_addr".to_string();

    // Execute first 10 blocks to get snapshot state
    let mut snapshot_state = initial.clone();
    for (txs, _) in chain.iter().take(10) {
        let (new_state, _, _) = execute_block(&snapshot_state, txs, 1, &proposer);
        snapshot_state = new_state;
    }

    // Replay blocks 11..20 from snapshot
    let mut state = snapshot_state;
    for (i, (txs, expected_root)) in chain.iter().skip(10).enumerate() {
        let (new_state, _, _) = execute_block(&state, txs, 1, &proposer);
        let got_root = new_state.root();
        assert_eq!(
            got_root, *expected_root,
            "State root mismatch at height {} on replay from snapshot",
            i + 11
        );
        state = new_state;
    }
}

/// Verify that empty blocks (no transactions) produce deterministic state roots.
#[test]
fn replay_empty_blocks() {
    let state = genesis_state();
    let proposer = "proposer_addr".to_string();

    let mut roots = Vec::new();
    let mut s = state.clone();
    for _ in 0..5 {
        let (new_state, _, _) = execute_block(&s, &[], 1, &proposer);
        roots.push(new_state.root());
        s = new_state;
    }

    // Replay
    let mut s2 = state;
    for (i, expected) in roots.iter().enumerate() {
        let (new_state, _, _) = execute_block(&s2, &[], 1, &proposer);
        assert_eq!(new_state.root(), *expected, "Empty block root mismatch at {}", i);
        s2 = new_state;
    }
}

/// Verify receipts are deterministic across replays.
#[test]
fn replay_receipts_deterministic() {
    let (initial, chain) = build_chain(10);
    let proposer = "proposer_addr".to_string();

    // First pass: collect receipts
    let mut state1 = initial.clone();
    let mut all_receipts1 = Vec::new();
    for (txs, _) in &chain {
        let (new_state, _, receipts) = execute_block(&state1, txs, 1, &proposer);
        all_receipts1.push(receipts);
        state1 = new_state;
    }

    // Second pass: verify receipts match
    let mut state2 = initial;
    for (i, (txs, _)) in chain.iter().enumerate() {
        let (new_state, _, receipts) = execute_block(&state2, txs, 1, &proposer);
        assert_eq!(
            receipts.len(),
            all_receipts1[i].len(),
            "Receipt count mismatch at height {}",
            i + 1
        );
        for (j, (r1, r2)) in all_receipts1[i].iter().zip(receipts.iter()).enumerate() {
            assert_eq!(r1.tx_hash, r2.tx_hash, "tx_hash mismatch h={} tx={}", i + 1, j);
            assert_eq!(r1.success, r2.success, "success mismatch h={} tx={}", i + 1, j);
            assert_eq!(r1.gas_used, r2.gas_used, "gas_used mismatch h={} tx={}", i + 1, j);
        }
        state2 = new_state;
    }
}

/// Verify state serialization roundtrip preserves root.
#[test]
fn replay_state_serialization_roundtrip() {
    let (initial, chain) = build_chain(5);
    let proposer = "proposer_addr".to_string();

    let mut state = initial;
    for (txs, _) in &chain {
        let (new_state, _, _) = execute_block(&state, txs, 1, &proposer);
        // Serialize and deserialize
        let json = serde_json::to_vec(&new_state).expect("serialize");
        let deserialized: KvState = serde_json::from_slice(&json).expect("deserialize");
        assert_eq!(
            new_state.root(),
            deserialized.root(),
            "State root changed after serialization roundtrip"
        );
        state = new_state;
    }
}
