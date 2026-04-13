//! Integration tests for IONA v22.
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

// ── In-memory block store ─────────────────────────────────────────────────

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

// ── Message collector outbox ──────────────────────────────────────────────

#[derive(Default, Clone)]
struct RecordingOutbox {
    pub broadcasts: Arc<Mutex<Vec<ConsensusMsg>>>,
    pub commits: Arc<Mutex<Vec<CommitCertificate>>>,
    pub store: MemBlockStore,
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

// ── Test helpers ──────────────────────────────────────────────────────────

fn make_keypairs(n: usize) -> Vec<Ed25519Keypair> {
    (1..=n)
        .map(|i| {
            let mut seed = [0u8; 32];
            seed[0] = i as u8;
            Ed25519Keypair::from_seed(seed)
        })
        .collect()
}

fn make_vset(keys: &[Ed25519Keypair]) -> ValidatorSet {
    ValidatorSet {
        vals: keys
            .iter()
            .map(|k| Validator {
                pk: k.public_key(),
                power: 100,
            })
            .collect(),
    }
}

fn make_stakes(keys: &[Ed25519Keypair]) -> StakeLedger {
    StakeLedger::default_demo_with(
        &keys.iter().map(|k| k.public_key()).collect::<Vec<_>>(),
        100,
    )
}

fn fast_config() -> Config {
    Config {
        propose_timeout_ms: 5000,
        prevote_timeout_ms: 5000,
        precommit_timeout_ms: 5000,
        max_rounds: 10,
        max_txs_per_block: 100,
        gas_target: 1_000_000,
        initial_base_fee_per_gas: 1,
        include_block_in_proposal: true,
        fast_quorum: true,
    }
}

fn drain_and_deliver(
    engines: &mut Vec<Engine<Ed25519Verifier>>,
    outboxes: &mut Vec<RecordingOutbox>,
    stores: &[MemBlockStore],
    keys: &[Ed25519Keypair],
) {
    // Collect all messages produced this round
    let mut pending: Vec<ConsensusMsg> = Vec::new();
    for ob in outboxes.iter_mut() {
        pending.extend(ob.broadcasts.lock().unwrap().drain(..));
    }

    // Deliver to every engine (including sender — simplest correct model)
    for (i, engine) in engines.iter_mut().enumerate() {
        for msg in &pending {
            let mut ob = outboxes[i].clone();
            let _ = engine.on_message(&keys[i], &stores[i], &mut ob, msg.clone());
        }
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────

/// 4 validators, 1 block commit without any Byzantine behavior.
#[test]
fn test_single_block_commit() {
    let keys = make_keypairs(4);
    let vset = make_vset(&keys);
    let cfg = fast_config();
    let state = KvState::default();
    let stakes = make_stakes(&keys);
    let stores: Vec<MemBlockStore> = (0..4).map(|_| MemBlockStore::default()).collect();

    let mut engines: Vec<Engine<Ed25519Verifier>> = keys
        .iter()
        .map(|_| {
            Engine::new(
                cfg.clone(),
                vset.clone(),
                1,
                Hash32::zero(),
                state.clone(),
                stakes.clone(),
                None,
            )
        })
        .collect();

    let mut outboxes: Vec<RecordingOutbox> = (0..4)
        .map(|_| RecordingOutbox {
            store: stores[0].clone(),
            ..Default::default()
        })
        .collect();

    // Tick the proposer — it will produce a proposal
    let proposer_idx = vset
        .vals
        .iter()
        .position(|v| v.pk == keys[0].public_key())
        .unwrap_or(0);
    {
        let mut ob = outboxes[proposer_idx].clone();
        engines[proposer_idx].tick(
            &keys[proposer_idx],
            &stores[proposer_idx],
            &mut ob,
            5001,
            |_| vec![],
        );
    }

    // Deliver messages and run until all commit
    for _round in 0..10 {
        drain_and_deliver(&mut engines, &mut outboxes, &stores, &keys);
        if engines.iter().all(|e| e.state.decided.is_some()) {
            break;
        }
        // Tick all to advance timeouts if needed
        for i in 0..4 {
            let mut ob = outboxes[i].clone();
            engines[i].tick(&keys[i], &stores[i], &mut ob, 100, |_| vec![]);
        }
        drain_and_deliver(&mut engines, &mut outboxes, &stores, &keys);
    }

    // All 4 validators must have decided
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

    // All commits must be at height 1
    for engine in &engines {
        assert_eq!(engine.state.decided.as_ref().unwrap().height, 1);
    }
}

/// Deterministic block ID: same header → same ID.
#[test]
fn test_block_id_deterministic() {
    use iona::types::BlockHeader;
    let header = BlockHeader {
        height: 1,
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
        chain_id: 6126151,
        timestamp: 0,
        protocol_version: 1,
    };
    let block1 = Block {
        header: header.clone(),
        txs: vec![],
    };
    let block2 = Block {
        header: header.clone(),
        txs: vec![],
    };
    assert_eq!(block1.id(), block2.id(), "block ID not deterministic");
}

/// tx_hash: same tx content → same hash regardless of insertion order.
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
    let mut s1 = KvState::default();
    s1.kv.insert("a".into(), "1".into());
    s1.kv.insert("b".into(), "2".into());
    s1.balances.insert("addr".into(), 100);

    let mut s2 = KvState::default();
    s2.balances.insert("addr".into(), 100);
    s2.kv.insert("b".into(), "2".into());
    s2.kv.insert("a".into(), "1".into());

    assert_eq!(s1.root(), s2.root(), "Merkle root not deterministic");
}

/// State Merkle root: different values → different root.
#[test]
fn test_merkle_root_sensitive() {
    let mut s1 = KvState::default();
    s1.kv.insert("k".into(), "v1".into());
    let mut s2 = KvState::default();
    s2.kv.insert("k".into(), "v2".into());
    assert_ne!(s1.root(), s2.root());
}

/// EIP-1559 base fee: fills up → fee goes up; empty → fee goes down.
#[test]
fn test_base_fee_adjustment() {
    let base = 100u64;
    let target = 1_000_000u64;

    let full = next_base_fee(base, target * 2, target); // full block
    let empty = next_base_fee(base, 0, target); // empty block

    assert!(full > base, "full block should increase base fee");
    assert!(empty < base, "empty block should decrease base fee");
}

/// Mempool: nonce ordering — must drain in ascending nonce order per sender.
#[test]
fn test_mempool_nonce_ordering() {
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
    mp.push(make_tx(2, 10)).unwrap();
    mp.push(make_tx(0, 10)).unwrap();
    mp.push(make_tx(1, 10)).unwrap();
    let drained = mp.drain_best(3);
    assert_eq!(drained[0].nonce, 0);
    assert_eq!(drained[1].nonce, 1);
    assert_eq!(drained[2].nonce, 2);
}

/// Mempool: RBF — replacement needs ≥10% bump, else rejected.
#[test]
fn test_mempool_rbf() {
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
    mp.push(make_tx(100)).unwrap();
    assert!(
        mp.push(make_tx(100)).is_err(),
        "same tip should be rejected"
    );
    assert!(mp.push(make_tx(110)).is_ok(), "10% bump should be accepted");
    assert_eq!(mp.metrics.rbf_replaced, 1);
}

/// Mempool: TTL expiry.
#[test]
fn test_mempool_ttl() {
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
    mp.push(tx).unwrap();
    assert_eq!(mp.len(), 1);
    mp.advance_height(10_000); // way past TTL
    assert_eq!(mp.len(), 0);
    assert_eq!(mp.metrics.expired, 1);
}

/// Block verification: modified block rejected, original accepted.
#[test]
fn test_verify_block_tamper() {
    use iona::execution::build_block;
    let state = KvState::default();
    let (block, _next_state, _receipts) = build_block(
        1,
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

    // Tampered state root fails
    let mut tampered = block.clone();
    tampered.header.state_root = Hash32([99u8; 32]);
    assert!(
        verify_block(&state, &tampered, "proposer").is_none(),
        "tampered state root should fail"
    );

    // Tampered gas_used fails
    let mut tampered2 = block.clone();
    tampered2.header.gas_used += 1;
    assert!(
        verify_block(&state, &tampered2, "proposer").is_none(),
        "tampered gas_used should fail"
    );
}

/// verify_block_with_vset: wrong proposer_pk rejected.
#[test]
fn test_verify_block_wrong_proposer() {
    use iona::crypto::PublicKeyBytes;
    use iona::execution::{build_block, verify_block_with_vset};

    let state = KvState::default();
    let real_pk = vec![1u8; 32];
    let fake_pk = vec![2u8; 32];

    let (block, _, _) = build_block(
        1,
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
        "block with wrong proposer_pk should be rejected"
    );
}

/// WAL: write + replay round-trips events.
#[test]
fn test_wal_roundtrip() {
    use iona::wal::{Wal, WalEvent};
    let dir = tempfile::tempdir().unwrap();
    let wal_path = dir.path().to_str().unwrap();
    {
        let mut wal = Wal::open(wal_path).unwrap();
        wal.append(&WalEvent::Note {
            msg: "hello".into(),
        })
        .unwrap();
        wal.append(&WalEvent::Step {
            height: 5,
            round: 0,
            step: "Propose".into(),
        })
        .unwrap();
    }
    let events = Wal::replay(wal_path).unwrap();
    assert_eq!(events.len(), 2);
    assert!(matches!(&events[0], WalEvent::Note { msg } if msg == "hello"));
    assert!(matches!(&events[1], WalEvent::Step { height: 5, .. }));
}
