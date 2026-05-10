//! Integration tests for IONA v30.
//!
//! Tests run multiple engine instances in-process, simulating a 4-validator
//! network with a mock message bus. No actual networking needed.
//!
//! Run with: cargo test --test integration

use iona::consensus::{
    BlockStore, CommitCertificate, Config, ConsensusMsg, Engine, Outbox, Validator, ValidatorSet,
};
use iona::crypto::ed25519::{Ed25519Keypair, Ed25519Verifier};
use iona::crypto::Signer;
use iona::execution::{execute_block, next_base_fee, verify_block, KvState};
use iona::mempool::Mempool;
use iona::slashing::StakeLedger;
use iona::types::{Block, Hash32, Receipt, Tx};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use thiserror::Error;
use tempfile::TempDir;

// -----------------------------------------------------------------------------
// Constants
// -----------------------------------------------------------------------------

/// Number of validators in the test network.
const NUM_VALIDATORS: usize = 4;

/// Default stake per validator.
const DEFAULT_STAKE: u64 = 100;

/// Default gas target for block processing.
const GAS_TARGET: u64 = 1_000_000;

/// Default propose timeout in milliseconds.
const PROPOSE_TIMEOUT_MS: u64 = 5000;

/// Default prevote timeout in milliseconds.
const PREVOTE_TIMEOUT_MS: u64 = 5000;

/// Default precommit timeout in milliseconds.
const PRECOMMIT_TIMEOUT_MS: u64 = 5000;

/// Default maximum rounds before consensus restarts.
const MAX_ROUNDS: u64 = 10;

/// Default maximum transactions per block.
const MAX_TXS_PER_BLOCK: usize = 100;

/// Initial base fee per gas.
const INITIAL_BASE_FEE: u64 = 1;

/// Chain ID for tests.
const TEST_CHAIN_ID: u64 = 6126151;

/// Genesis height.
const GENESIS_HEIGHT: u64 = 1;

// -----------------------------------------------------------------------------
// Errors
// -----------------------------------------------------------------------------

/// Integration test errors.
#[derive(Debug, Error)]
pub enum IntegrationTestError {
    #[error("consensus did not commit within {rounds} rounds")]
    Timeout { rounds: u64 },

    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("mempool error: {0}")]
    Mempool(String),

    #[error("serialisation error: {0}")]
    Serialization(#[from] serde_json::Error),
}

pub type IntegrationTestResult<T> = Result<T, IntegrationTestError>;

// -----------------------------------------------------------------------------
// Helpers
// -----------------------------------------------------------------------------

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

/// Create a validator set from a list of keypairs.
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

/// Create a stake ledger for the given validators.
fn make_stake_ledger(keys: &[Ed25519Keypair]) -> StakeLedger {
    StakeLedger::default_demo_with(
        &keys.iter().map(|k| k.public_key()).collect::<Vec<_>>(),
        DEFAULT_STAKE,
    )
}

/// Fast consensus configuration for tests.
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

// -----------------------------------------------------------------------------
// In‑memory block store
// -----------------------------------------------------------------------------

#[derive(Default, Clone)]
struct MemBlockStore(Arc<Mutex<HashMap<Hash32, Block>>>);

impl BlockStore for MemBlockStore {
    fn get(&self, id: &Hash32) -> Option<Block> {
        self.0.lock().unwrap().get(id).cloned()
    }

    fn put(&self, block: Block) {
        let id = block.id();
        self.0.lock().unwrap().insert(id, block);
    }
}

// -----------------------------------------------------------------------------
// Recording outbox for message collection
// -----------------------------------------------------------------------------

#[derive(Default, Clone)]
struct RecordingOutbox {
    broadcasts: Arc<Mutex<Vec<ConsensusMsg>>>,
    commits: Arc<Mutex<Vec<CommitCertificate>>>,
    store: MemBlockStore,
}

impl Outbox for RecordingOutbox {
    fn broadcast(&mut self, msg: ConsensusMsg) {
        self.broadcasts.lock().unwrap().push(msg);
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
        self.commits.lock().unwrap().push(cert.clone());
    }
}

// -----------------------------------------------------------------------------
// Message delivery
// -----------------------------------------------------------------------------

/// Collect all pending messages from outboxes and deliver them to all engines.
fn drain_and_deliver(
    engines: &mut [Engine<Ed25519Verifier>],
    outboxes: &mut [RecordingOutbox],
    stores: &[MemBlockStore],
    keys: &[Ed25519Keypair],
) {
    let mut pending = Vec::new();
    for ob in outboxes.iter_mut() {
        pending.extend(ob.broadcasts.lock().unwrap().drain(..));
    }

    for (i, engine) in engines.iter_mut().enumerate() {
        for msg in &pending {
            let mut ob = outboxes[i].clone();
            let _ = engine.on_message(&keys[i], &stores[i], &mut ob, msg.clone());
        }
    }
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

/// 4 validators, 1 block commit without any Byzantine behaviour.
#[test]
fn test_single_block_commit() -> IntegrationTestResult<()> {
    let keys = make_keypairs(NUM_VALIDATORS);
    let vset = make_validator_set(&keys);
    let config = fast_config();
    let state = KvState::default();
    let stakes = make_stake_ledger(&keys);
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
                state.clone(),
                stakes.clone(),
                None,
            )
        })
        .collect();

    let mut outboxes: Vec<RecordingOutbox> = (0..NUM_VALIDATORS)
        .map(|_| RecordingOutbox {
            store: stores[0].clone(),
            ..Default::default()
        })
        .collect();

    let proposer_idx = vset
        .vals
        .iter()
        .position(|v| v.pk == keys[0].public_key())
        .unwrap_or(0);

    // Tick the proposer – it will produce a proposal
    {
        let mut ob = outboxes[proposer_idx].clone();
        engines[proposer_idx].tick(
            &keys[proposer_idx],
            &stores[proposer_idx],
            &mut ob,
            PROPOSE_TIMEOUT_MS + 1,
            |_| vec![],
        );
    }

    let max_rounds = MAX_ROUNDS as u64;
    for round in 0..max_rounds {
        drain_and_deliver(&mut engines, &mut outboxes, &stores, &keys);
        if engines.iter().all(|e| e.state.decided.is_some()) {
            break;
        }
        // Tick all to advance timeouts if needed
        for i in 0..NUM_VALIDATORS {
            let mut ob = outboxes[i].clone();
            engines[i].tick(&keys[i], &stores[i], &mut ob, 100, |_| vec![]);
        }
        drain_and_deliver(&mut engines, &mut outboxes, &stores, &keys);

        if round == max_rounds - 1 {
            return Err(IntegrationTestError::Timeout { rounds: max_rounds });
        }
    }

    // All validators must have decided
    for (i, engine) in engines.iter().enumerate() {
        assert!(engine.state.decided.is_some(), "engine {i} did not commit");
    }

    // All must have decided on the SAME block
    let block_ids: Vec<_> = engines
        .iter()
        .map(|e| e.state.decided.as_ref().unwrap().block_id.clone())
        .collect();
    assert!(
        block_ids.windows(2).all(|w| w[0] == w[1]),
        "engines committed different blocks: {:?}",
        block_ids
    );

    // All commits must be at the genesis height
    for engine in &engines {
        assert_eq!(engine.state.decided.as_ref().unwrap().height, GENESIS_HEIGHT);
    }

    Ok(())
}

/// Deterministic block ID: same header → same ID.
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
    let block2 = Block {
        header,
        txs: vec![],
    };
    assert_eq!(block1.id(), block2.id(), "block ID not deterministic");
}

/// `tx_hash`: same transaction content → same hash regardless of insertion order.
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
    assert_eq!(h1, h2);
}

/// State Merkle root: same KV content → same root regardless of insertion order.
#[test]
fn test_merkle_root_deterministic() {
    let mut state1 = KvState::default();
    state1.kv.insert("a".into(), "1".into());
    state1.kv.insert("b".into(), "2".into());
    state1.balances.insert("addr".into(), 100);

    let mut state2 = KvState::default();
    state2.balances.insert("addr".into(), 100);
    state2.kv.insert("b".into(), "2".into());
    state2.kv.insert("a".into(), "1".into());

    assert_eq!(state1.root(), state2.root(), "Merkle root not deterministic");
}

/// State Merkle root: different values → different root.
#[test]
fn test_merkle_root_sensitive() {
    let mut state1 = KvState::default();
    state1.kv.insert("k".into(), "v1".into());
    let mut state2 = KvState::default();
    state2.kv.insert("k".into(), "v2".into());
    assert_ne!(state1.root(), state2.root());
}

/// EIP‑1559 base fee: full block → fee increases; empty block → fee decreases.
#[test]
fn test_base_fee_adjustment() {
    let base = 100u64;
    let target = GAS_TARGET;

    let full = next_base_fee(base, target * 2, target);
    let empty = next_base_fee(base, 0, target);

    assert!(full > base, "full block should increase base fee");
    assert!(empty < base, "empty block should decrease base fee");
}

/// Mempool: nonce ordering – must drain in ascending nonce order per sender.
#[test]
fn test_mempool_nonce_ordering() -> IntegrationTestResult<()> {
    let mut mp = Mempool::new(1000);
    let make_tx = |nonce: u64, tip: u64| Tx {
        pubkey: vec![0u8; 32],
        from: "alice".into(),
        nonce,
        max_fee_per_gas: tip + 10,
        max_priority_fee_per_gas: tip,
        gas_limit: 50_000,
        payload: "set k v".into(),
        signature: vec![0u8; 64],
        chain_id: 1,
    };

    mp.push(make_tx(2, 10)).map_err(|e| IntegrationTestError::Mempool(e.to_string()))?;
    mp.push(make_tx(0, 10)).map_err(|e| IntegrationTestError::Mempool(e.to_string()))?;
    mp.push(make_tx(1, 10)).map_err(|e| IntegrationTestError::Mempool(e.to_string()))?;

    let drained = mp.drain_best(3);
    assert_eq!(drained[0].nonce, 0);
    assert_eq!(drained[1].nonce, 1);
    assert_eq!(drained[2].nonce, 2);
    Ok(())
}

/// Mempool: RBF – replacement needs ≥10% bump, otherwise rejected.
#[test]
fn test_mempool_rbf() -> IntegrationTestResult<()> {
    let mut mp = Mempool::new(1000);
    let make_tx = |tip: u64| Tx {
        pubkey: vec![0u8; 32],
        from: "bob".into(),
        nonce: 0,
        max_fee_per_gas: tip + 10,
        max_priority_fee_per_gas: tip,
        gas_limit: 50_000,
        payload: "set k v".into(),
        signature: vec![0u8; 64],
        chain_id: 1,
    };

    mp.push(make_tx(100)).map_err(|e| IntegrationTestError::Mempool(e.to_string()))?;
    assert!(
        mp.push(make_tx(100)).is_err(),
        "same tip should be rejected"
    );
    assert!(
        mp.push(make_tx(110)).is_ok(),
        "10% bump should be accepted"
    );
    assert_eq!(mp.metrics.rbf_replaced, 1);
    Ok(())
}

/// Mempool: TTL expiry.
#[test]
fn test_mempool_ttl() -> IntegrationTestResult<()> {
    let mut mp = Mempool::new(1000);
    let tx = Tx {
        pubkey: vec![0u8; 32],
        from: "carol".into(),
        nonce: 0,
        max_fee_per_gas: 10,
        max_priority_fee_per_gas: 5,
        gas_limit: 50_000,
        payload: "set k v".into(),
        signature: vec![0u8; 64],
        chain_id: 1,
    };
    mp.push(tx).map_err(|e| IntegrationTestError::Mempool(e.to_string()))?;
    assert_eq!(mp.len(), 1);
    mp.advance_height(10_000);
    assert_eq!(mp.len(), 0);
    assert_eq!(mp.metrics.expired, 1);
    Ok(())
}

/// Block verification: modified block rejected, original accepted.
#[test]
fn test_verify_block_tamper() {
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

    // Valid block passes
    assert!(
        verify_block(&state, &block, "proposer").is_some(),
        "valid block should pass"
    );

    let mut tampered = block.clone();
    tampered.header.state_root = Hash32([99u8; 32]);
    assert!(
        verify_block(&state, &tampered, "proposer").is_none(),
        "tampered state root should fail"
    );

    let mut tampered2 = block;
    tampered2.header.gas_used += 1;
    assert!(
        verify_block(&state, &tampered2, "proposer").is_none(),
        "tampered gas used should fail"
    );
}

/// `verify_block_with_vset`: wrong proposer key rejected.
#[test]
fn test_verify_block_wrong_proposer() {
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

    let correct = PublicKeyBytes(real_pk);
    let wrong = PublicKeyBytes(fake_pk);

    assert!(verify_block_with_vset(&state, &block, "proposer", &correct).is_some());
    assert!(
        verify_block_with_vset(&state, &block, "proposer", &wrong).is_none(),
        "block with wrong proposer should be rejected"
    );
}

/// WAL: write + replay round‑trips events.
#[test]
fn test_wal_roundtrip() -> IntegrationTestResult<()> {
    use iona::wal::{Wal, WalEvent};

    let dir = TempDir::new()?;
    let path = dir.path();
    {
        let mut wal = Wal::open(path)?;
        wal.append(&WalEvent::Note {
            msg: "hello".into(),
        })?;
        wal.append(&WalEvent::Step {
            height: 5,
            round: 0,
            step: "Propose".into(),
        })?;
    }
    let events = Wal::replay(path)?;
    assert_eq!(events.len(), 2);
    assert!(matches!(&events[0], WalEvent::Note { msg } if msg == "hello"));
    assert!(matches!(&events[1], WalEvent::Step { height: 5, .. }));
    Ok(())
}
