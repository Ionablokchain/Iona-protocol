//! Integration tests for the IONA consensus pipeline.
//!
//! Exercise multiple subsystems together — consensus engine, mempool,
//! execution, WAL — with a multi-validator setup. These tests complement
//! the per-module unit tests by exercising the seams between components.
//!
//! # Scope
//!
//! * **Consensus** — single-round block commit across 4 honest validators
//! * **Determinism** — smoke checks for consensus-critical primitives
//!   (the authoritative pinning lives in `tests/golden_vectors.rs`)
//! * **Fee market** — EIP-1559 base-fee adjustment
//! * **Mempool** — nonce ordering, RBF, TTL, per-sender limits
//! * **Execution** — block verification rejects tampering and wrong proposers
//! * **WAL** — write/replay round-trip
//!
//! Run with: `cargo test --test integration`

use iona::consensus::{
    BlockStore, CommitCertificate, Config, ConsensusMsg, Engine, Outbox, Validator, ValidatorSet,
};
use iona::crypto::ed25519::{Ed25519Keypair, Ed25519Verifier};
use iona::crypto::Signer;
use iona::execution::{next_base_fee, verify_block, KvState};
use iona::mempool::Mempool;
use iona::slashing::StakeLedger;
use iona::types::{Block, Hash32, Receipt, Tx};

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use tempfile::TempDir;
use thiserror::Error;

// ---------------------------------------------------------------------------
// Test configuration
// ---------------------------------------------------------------------------

/// Number of validators in the test network.
const NUM_VALIDATORS: usize = 4;

/// Stake per validator.
const DEFAULT_STAKE: u64 = 100;

/// EIP-1559 gas target.
const GAS_TARGET: u64 = 1_000_000;

/// Propose / prevote / precommit timeouts, in milliseconds.
///
/// These are *virtual* time advances fed to `Engine::tick`, not real
/// sleeps. Keeping them large ensures that a healthy proposer acts on
/// the first tick; keeping the per-round fallback small ensures the
/// test fails fast if consensus stalls.
const PROPOSE_TIMEOUT_MS: u64 = 5000;
const PREVOTE_TIMEOUT_MS: u64 = 5000;
const PRECOMMIT_TIMEOUT_MS: u64 = 5000;

/// Maximum rounds before consensus is declared stalled.
const MAX_ROUNDS: u64 = 10;

/// Maximum transactions per block.
const MAX_TXS_PER_BLOCK: usize = 100;

/// Initial base fee per gas.
const INITIAL_BASE_FEE: u64 = 1;

/// Chain ID used by test transactions and blocks.
const TEST_CHAIN_ID: u64 = 6_126_151;

/// Genesis height for the test chain.
const GENESIS_HEIGHT: u64 = 1;

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

#[derive(Debug, Error)]
pub enum IntegrationTestError {
    #[error("consensus did not commit within {rounds} rounds")]
    Timeout { rounds: u64 },

    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("mempool error: {0}")]
    Mempool(String),

    #[error("serialization error: {0}")]
    Serialization(#[from] serde_json::Error),
}

pub type IntegrationTestResult<T> = Result<T, IntegrationTestError>;

// ---------------------------------------------------------------------------
// Key / validator / config construction
// ---------------------------------------------------------------------------

/// Generate `n` Ed25519 keypairs with deterministic seeds.
fn make_keypairs(n: usize) -> Vec<Ed25519Keypair> {
    (1..=n)
        .map(|i| {
            let mut seed = [0u8; 32];
            seed[0] = i as u8;
            Ed25519Keypair::from_seed(seed)
        })
        .collect()
}

fn make_validator_set(keys: &[Ed25519Keypair]) -> ValidatorSet {
    ValidatorSet {
        vals: keys
            .iter()
            .map(|k| Validator {
                pk: k.public_key(),
                power: DEFAULT_STAKE,
            })
            .collect(),
    }
}

fn make_stake_ledger(keys: &[Ed25519Keypair]) -> StakeLedger {
    let pks: Vec<_> = keys.iter().map(|k| k.public_key()).collect();
    StakeLedger::default_demo_with(&pks, DEFAULT_STAKE)
}

fn fast_config() -> Config {
    Config {
        propose_timeout_ms: PROPOSE_TIMEOUT_MS,
        prevote_timeout_ms: PREVOTE_TIMEOUT_MS,
        precommit_timeout_ms: PRECOMMIT_TIMEOUT_MS,
        max_rounds: MAX_ROUNDS,
        max_txs_per_block: MAX_TXS_PER_BLOCK,
        gas_target: GAS_TARGET,
        initial_base_fee_per_gas: INITIAL_BASE_FEE,
        include_block_in_proposal: true,
        fast_quorum: true,
    }
}

// ---------------------------------------------------------------------------
// Block store
// ---------------------------------------------------------------------------

/// In-memory block store, cheaply cloneable (shared state via `Arc`).
#[derive(Default, Clone)]
struct MemBlockStore(Arc<Mutex<HashMap<Hash32, Block>>>);

impl BlockStore for MemBlockStore {
    fn get(&self, id: &Hash32) -> Option<Block> {
        self.0.lock().ok()?.get(id).cloned()
    }

    fn put(&self, block: Block) {
        let id = block.id();
        if let Ok(mut m) = self.0.lock() {
            m.insert(id, block);
        }
    }
}

// ---------------------------------------------------------------------------
// Recording outbox
// ---------------------------------------------------------------------------

/// Outbox that records every broadcast and commit certificate for later
/// inspection, while forwarding block storage to the shared `MemBlockStore`.
#[derive(Default, Clone)]
struct RecordingOutbox {
    broadcasts: Arc<Mutex<Vec<ConsensusMsg>>>,
    commits: Arc<Mutex<Vec<CommitCertificate>>>,
    store: MemBlockStore,
}

impl Outbox for RecordingOutbox {
    fn broadcast(&mut self, msg: ConsensusMsg) {
        if let Ok(mut b) = self.broadcasts.lock() {
            b.push(msg);
        }
    }

    fn request_block(&mut self, _id: Hash32) {}

    fn on_commit(
        &mut self,
        cert: &CommitCertificate,
        _block: &Block,
        _state: &KvState,
        _base_fee: u64,
        _receipts: &[Receipt],
    ) {
        if let Ok(mut c) = self.commits.lock() {
            c.push(cert.clone());
        }
    }
}

// ---------------------------------------------------------------------------
// Message delivery
// ---------------------------------------------------------------------------

/// Drain every pending broadcast from all outboxes, then deliver the full
/// batch to every engine. Returns the number of messages that were
/// delivered (0 means the network was already quiescent).
fn drain_and_deliver(
    engines: &mut [Engine<Ed25519Verifier>],
    outboxes: &mut [RecordingOutbox],
    stores: &[MemBlockStore],
    keys: &[Ed25519Keypair],
) -> usize {
    let mut pending = Vec::new();
    for ob in outboxes.iter_mut() {
        if let Ok(mut b) = ob.broadcasts.lock() {
            pending.extend(b.drain(..));
        }
    }

    for (i, engine) in engines.iter_mut().enumerate() {
        for msg in &pending {
            let mut ob = outboxes[i].clone();
            let _ = engine.on_message(&keys[i], &stores[i], &mut ob, msg.clone());
        }
    }

    pending.len()
}

// ===========================================================================
// Consensus integration
// ===========================================================================

/// Single round of 4 honest validators must commit one block, and every
/// engine must agree on the same block ID.
#[test]
fn test_single_block_commit() -> IntegrationTestResult<()> {
    let keys = make_keypairs(NUM_VALIDATORS);
    let vset = make_validator_set(&keys);
    let stakes = make_stake_ledger(&keys);
    let config = fast_config();

    let stores: Vec<MemBlockStore> = (0..NUM_VALIDATORS)
        .map(|_| MemBlockStore::default())
        .collect();

    let mut engines: Vec<Engine<Ed25519Verifier>> = keys
        .iter()
        .map(|_| {
            Engine::new(
                config.clone(),
                vset.clone(),
                GENESIS_HEIGHT,
                Hash32::zero(),
                KvState::default(),
                stakes.clone(),
                None,
            )
        })
        .collect();

    let mut outboxes: Vec<RecordingOutbox> = (0..NUM_VALIDATORS)
        .map(|i| RecordingOutbox {
            store: stores[i].clone(),
            ..Default::default()
        })
        .collect();

    // The proposer at (GENESIS_HEIGHT, round=0) is `(height + round) % n`.
    let proposer_idx = ((GENESIS_HEIGHT) as usize) % NUM_VALIDATORS;

    // First tick: advance past the propose timeout on the *actual*
    // proposer so it emits a proposal.
    let mut now_ms = PROPOSE_TIMEOUT_MS + 1;
    {
        let mut ob = outboxes[proposer_idx].clone();
        engines[proposer_idx].tick(
            &keys[proposer_idx],
            &stores[proposer_idx],
            &mut ob,
            now_ms,
            |_| vec![],
        );
    }

    // Pump the network. If it goes quiet before all engines have decided,
    // advance virtual time to trigger the next timeout tier.
    let mut committed = false;
    for _round in 0..MAX_ROUNDS {
        let delivered = drain_and_deliver(&mut engines, &mut outboxes, &stores, &keys);
        if engines.iter().all(|e| e.state.decided.is_some()) {
            committed = true;
            break;
        }
        if delivered == 0 {
            now_ms += PROPOSE_TIMEOUT_MS;
            for i in 0..NUM_VALIDATORS {
                let mut ob = outboxes[i].clone();
                engines[i].tick(&keys[i], &stores[i], &mut ob, now_ms, |_| vec![]);
            }
        }
    }

    if !committed {
        return Err(IntegrationTestError::Timeout { rounds: MAX_ROUNDS });
    }

    // Every engine must have decided on the same block at the genesis height.
    let decided: Vec<&iona::consensus::Decided> = engines
        .iter()
        .map(|e| {
            e.state
                .decided
                .as_ref()
                .expect("every engine must have decided")
        })
        .collect();

    let first_id = &decided[0].block_id;
    for (i, d) in decided.iter().enumerate() {
        assert_eq!(
            &d.block_id, first_id,
            "engine {i} decided a different block than engine 0"
        );
        assert_eq!(
            d.height, GENESIS_HEIGHT,
            "engine {i} decided at the wrong height"
        );
    }

    // At least one commit certificate must have been emitted.
    let total_commits: usize = outboxes
        .iter()
        .map(|ob| ob.commits.lock().map(|c| c.len()).unwrap_or(0))
        .sum();
    assert!(
        total_commits > 0,
        "at least one outbox must have recorded a commit certificate"
    );

    Ok(())
}

// ===========================================================================
// Determinism smoke checks
//
// The authoritative golden vectors live in `tests/golden_vectors.rs`. These
// are integration-level smoke checks that the primitives behave
// deterministically when exercised through the public module paths.
// ===========================================================================

#[test]
fn test_block_id_deterministic() {
    use iona::types::BlockHeader;

    let header = BlockHeader {
        height: GENESIS_HEIGHT,
        round: 0,
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
        timestamp: 0,
        protocol_version: 1,
    };

    let block1 = Block {
        header: header.clone(),
        txs: vec![],
    };
    let block2 = Block { header, txs: vec![] };
    assert_eq!(block1.id(), block2.id(), "block ID not deterministic");

    let mut header3 = block1.header.clone();
    header3.height = 2;
    let block3 = Block {
        header: header3,
        txs: vec![],
    };
    assert_ne!(
        block1.id(),
        block3.id(),
        "different height must yield different block ID"
    );
}

#[test]
fn test_tx_hash_deterministic() {
    let tx = Tx {
        pubkey: vec![1u8; 32],
        from: "abc".into(),
        nonce: 0,
        max_fee_per_gas: 10,
        max_priority_fee_per_gas: 5,
        gas_limit: 50_000,
        payload: "set k v".into(),
        signature: vec![0u8; 64],
        chain_id: 1,
    };
    let h1 = iona::types::tx_hash(&tx);
    let h2 = iona::types::tx_hash(&tx);
    assert_eq!(h1, h2, "tx hash not deterministic");

    let mut tx2 = tx.clone();
    tx2.nonce = 1;
    assert_ne!(
        h1,
        iona::types::tx_hash(&tx2),
        "different nonce must yield different tx hash"
    );
}

#[test]
fn test_state_root_deterministic() {
    let mut state1 = KvState::default();
    state1.kv.insert("a".into(), "1".into());
    state1.kv.insert("b".into(), "2".into());
    state1.balances.insert("addr".into(), 100);

    let mut state2 = KvState::default();
    state2.balances.insert("addr".into(), 100);
    state2.kv.insert("b".into(), "2".into());
    state2.kv.insert("a".into(), "1".into());

    assert_eq!(
        state1.root(),
        state2.root(),
        "state root must not depend on insertion order"
    );
}

#[test]
fn test_state_root_sensitive_to_values() {
    let mut state1 = KvState::default();
    state1.kv.insert("k".into(), "v1".into());

    let mut state2 = KvState::default();
    state2.kv.insert("k".into(), "v2".into());

    assert_ne!(
        state1.root(),
        state2.root(),
        "different values must yield different state roots"
    );
}

// ===========================================================================
// Fee market
// ===========================================================================

#[test]
fn test_base_fee_adjustment() {
    let base = 100u64;
    let target = GAS_TARGET;

    let full = next_base_fee(base, target * 2, target);
    let empty = next_base_fee(base, 0, target);

    assert!(full > base, "full block must raise base fee (got {full})");
    assert!(empty < base, "empty block must lower base fee (got {empty})");
    assert!(full > empty, "full must cost more than empty");
}

// ===========================================================================
// Mempool
// ===========================================================================

fn tx_from(from: &str, nonce: u64, tip: u64, payload: String) -> Tx {
    Tx {
        pubkey: vec![0u8; 32],
        from: from.into(),
        nonce,
        max_fee_per_gas: tip + 10,
        max_priority_fee_per_gas: tip,
        gas_limit: 50_000,
        payload,
        signature: vec![0u8; 64],
        chain_id: 1,
    }
}

#[test]
fn test_mempool_nonce_ordering() -> IntegrationTestResult<()> {
    let mut mp = Mempool::new(1000);

    for nonce in [2u64, 0, 1] {
        mp.push(tx_from("alice", nonce, 10, format!("set k{nonce} v")))
            .map_err(|e| IntegrationTestError::Mempool(e.to_string()))?;
    }

    let drained = mp.drain_best(3);
    assert_eq!(drained.len(), 3, "must drain exactly 3 transactions");
    assert_eq!(drained[0].nonce, 0);
    assert_eq!(drained[1].nonce, 1);
    assert_eq!(drained[2].nonce, 2);
    assert_eq!(mp.len(), 0, "pool must be empty after full drain");
    Ok(())
}

#[test]
fn test_mempool_rbf() -> IntegrationTestResult<()> {
    let mut mp = Mempool::new(1000);

    mp.push(tx_from("bob", 0, 100, "v0".into()))
        .map_err(|e| IntegrationTestError::Mempool(e.to_string()))?;

    // Same tip → rejected.
    assert!(
        mp.push(tx_from("bob", 0, 100, "v1".into())).is_err(),
        "same tip must be rejected"
    );
    // 9% bump → rejected (< 10% threshold).
    assert!(
        mp.push(tx_from("bob", 0, 109, "v2".into())).is_err(),
        "9% bump must be rejected"
    );
    // 10% bump → accepted.
    assert!(
        mp.push(tx_from("bob", 0, 110, "v3".into())).is_ok(),
        "10% bump must be accepted"
    );
    assert_eq!(mp.metrics.rbf_replaced, 1);
    Ok(())
}

#[test]
fn test_mempool_ttl() -> IntegrationTestResult<()> {
    let mut mp = Mempool::new(1000);

    mp.push(tx_from("carol", 0, 5, "v".into()))
        .map_err(|e| IntegrationTestError::Mempool(e.to_string()))?;
    assert_eq!(mp.len(), 1);

    mp.advance_height(10_000);
    assert_eq!(mp.len(), 0, "transaction must expire after TTL");
    assert_eq!(mp.metrics.expired, 1);
    Ok(())
}

/// Every sender has a finite pending-transaction limit. Probe the limit
/// instead of hard-coding it, so the test does not break silently when
/// the policy constant changes.
#[test]
fn test_mempool_sender_queue_limit() -> IntegrationTestResult<()> {
    let mut mp = Mempool::new(1000);
    let mut accepted = 0usize;
    let mut hit_limit = false;

    for nonce in 0..500u64 {
        let tx = tx_from("alice", nonce, 5, format!("set k{nonce} v"));
        match mp.push(tx) {
            Ok(()) => accepted += 1,
            Err(_) => {
                hit_limit = true;
                break;
            }
        }
    }

    assert!(
        hit_limit,
        "sender queue must have a finite limit (accepted {accepted} txs with no rejection)"
    );
    assert!(
        accepted > 0,
        "sender must accept at least one transaction before the limit"
    );
    assert_eq!(
        mp.len(),
        accepted,
        "all accepted transactions must remain in the pool"
    );
    Ok(())
}

// ===========================================================================
// Block verification
// ===========================================================================

#[test]
fn test_verify_block_rejects_tampering() {
    use iona::execution::build_block;

    let state = KvState::default();
    let (block, _next_state, _receipts) = build_block(
        GENESIS_HEIGHT,
        0,
        Hash32::zero(),
        vec![0u8; 32],
        "proposer",
        &state,
        1,
        vec![],
    );

    assert!(
        verify_block(&state, &block, "proposer").is_some(),
        "pristine block must verify"
    );

    let mut tampered_root = block.clone();
    tampered_root.header.state_root = Hash32([99u8; 32]);
    assert!(
        verify_block(&state, &tampered_root, "proposer").is_none(),
        "tampered state root must be rejected"
    );

    let mut tampered_gas = block.clone();
    tampered_gas.header.gas_used = tampered_gas.header.gas_used.saturating_add(1);
    assert!(
        verify_block(&state, &tampered_gas, "proposer").is_none(),
        "tampered gas_used must be rejected"
    );

    let mut tampered_fee = block;
    tampered_fee.header.base_fee_per_gas = tampered_fee.header.base_fee_per_gas.saturating_add(1);
    assert!(
        verify_block(&state, &tampered_fee, "proposer").is_none(),
        "tampered base_fee must be rejected"
    );
}

#[test]
fn test_verify_block_rejects_wrong_proposer() {
    use iona::crypto::PublicKeyBytes;
    use iona::execution::{build_block, verify_block_with_vset};

    let state = KvState::default();
    let real_pk = vec![1u8; 32];
    let fake_pk = vec![2u8; 32];

    let (block, _, _) = build_block(
        GENESIS_HEIGHT,
        0,
        Hash32::zero(),
        real_pk.clone(),
        "proposer",
        &state,
        1,
        vec![],
    );

    assert!(
        verify_block_with_vset(&state, &block, "proposer", &PublicKeyBytes(real_pk)).is_some(),
        "correct proposer must be accepted"
    );
    assert!(
        verify_block_with_vset(&state, &block, "proposer", &PublicKeyBytes(fake_pk)).is_none(),
        "wrong proposer must be rejected"
    );
}

// ===========================================================================
// WAL
// ===========================================================================

#[test]
fn test_wal_roundtrip() -> IntegrationTestResult<()> {
    use iona::wal::{Wal, WalEvent};

    let dir = TempDir::new()?;
    {
        let mut wal = Wal::open(dir.path())?;
        wal.append(&WalEvent::Note {
            msg: "hello".into(),
        })?;
        wal.append(&WalEvent::Step {
            height: 5,
            round: 0,
            step: "Propose".into(),
        })?;
    }

    let events = Wal::replay(dir.path())?;
    assert_eq!(events.len(), 2, "WAL must replay exactly two events");
    assert!(
        matches!(&events[0], WalEvent::Note { msg } if msg == "hello"),
        "first event must be the recorded Note"
    );
    assert!(
        matches!(&events[1], WalEvent::Step { height: 5, .. }),
        "second event must be the recorded Step at height 5"
    );
    Ok(())
}

#[test]
fn test_wal_empty_replay() -> IntegrationTestResult<()> {
    use iona::wal::Wal;

    let dir = TempDir::new()?;
    let events = Wal::replay(dir.path())?;
    assert!(events.is_empty(), "empty WAL must replay to no events");
    Ok(())
}
