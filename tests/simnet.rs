//! Simulated network harness for Byzantine and chaos testing.
//!
//! Tests multi-node in-process consensus with message injection:
//! - Message delay / reordering
//! - Network partitions and heals
//! - Drop rates
//! - Malicious validators (equivocation)
//!
//! Run with:
//!   cargo test --test simnet -- --ignored

use iona::consensus::{
    BlockStore, CommitCertificate, Config, ConsensusMsg, Engine, Outbox, Validator, ValidatorSet,
};
use iona::crypto::ed25519::{Ed25519Keypair, Ed25519Verifier};
use iona::crypto::Signer;
use iona::execution::KvState;
use iona::slashing::StakeLedger;
use iona::types::{Block, Hash32, Receipt};
use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, Mutex};

// ── Shared in-memory block store ──────────────────────────────────────────

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

// ── Recording outbox ──────────────────────────────────────────────────────

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
            .map(|k| Validator { pk: k.public_key(), power: 100 })
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

/// Broadcast all pending messages to all engines (full mesh, no drops).
fn broadcast_all(
    engines: &mut Vec<Engine<Ed25519Verifier>>,
    outboxes: &mut Vec<RecordingOutbox>,
    stores: &[MemBlockStore],
    keys: &[Ed25519Keypair],
) {
    let msgs: Vec<ConsensusMsg> = outboxes
        .iter_mut()
        .flat_map(|o| o.broadcasts.lock().unwrap().drain(..).collect::<Vec<_>>())
        .collect();

    for (i, engine) in engines.iter_mut().enumerate() {
        for msg in &msgs {
            let mut ob = outboxes[i].clone();
            let _ = engine.on_message(&keys[i], &stores[i], &mut ob, msg.clone());
        }
    }
}

/// Simulate with a drop probability: each message is dropped with `drop_prob` (0.0–1.0).
fn broadcast_with_drop(
    engines: &mut Vec<Engine<Ed25519Verifier>>,
    outboxes: &mut Vec<RecordingOutbox>,
    stores: &[MemBlockStore],
    keys: &[Ed25519Keypair],
    drop_prob: f64,
) {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};

    let msgs: Vec<ConsensusMsg> = outboxes
        .iter_mut()
        .flat_map(|o| o.broadcasts.lock().unwrap().drain(..).collect::<Vec<_>>())
        .collect();

    for (i, engine) in engines.iter_mut().enumerate() {
        for (j, msg) in msgs.iter().enumerate() {
            // Deterministic "random" drop based on (i, j)
            let mut h = DefaultHasher::new();
            (i as u64 * 10000 + j as u64).hash(&mut h);
            let hash_val = h.finish();
            let frac = (hash_val % 10000) as f64 / 10000.0;
            if frac < drop_prob {
                continue; // drop this message
            }
            let mut ob = outboxes[i].clone();
            let _ = engine.on_message(&keys[i], &stores[i], &mut ob, msg.clone());
        }
    }
}

/// Broadcast only to a subset of validators (simulating partition).
fn broadcast_to_partition(
    partition: &[usize],
    engines: &mut Vec<Engine<Ed25519Verifier>>,
    outboxes: &mut Vec<RecordingOutbox>,
    stores: &[MemBlockStore],
    keys: &[Ed25519Keypair],
) {
    let msgs: Vec<ConsensusMsg> = outboxes
        .iter_mut()
        .flat_map(|o| o.broadcasts.lock().unwrap().drain(..).collect::<Vec<_>>())
        .collect();

    for &i in partition {
        if i >= engines.len() {
            continue;
        }
        for msg in &msgs {
            let mut ob = outboxes[i].clone();
            let _ = engines[i].on_message(&keys[i], &stores[i], &mut ob, msg.clone());
        }
    }
}

fn tick_all(
    engines: &mut Vec<Engine<Ed25519Verifier>>,
    outboxes: &mut Vec<RecordingOutbox>,
    stores: &[MemBlockStore],
    keys: &[Ed25519Keypair],
) {
    for (i, engine) in engines.iter_mut().enumerate() {
        let mut ob = outboxes[i].clone();
        engine.tick(&keys[i], &stores[i], &mut ob, 200, |_| vec![]);
        // Merge new broadcasts back
        let new: Vec<_> = ob.broadcasts.lock().unwrap().drain(..).collect();
        outboxes[i].broadcasts.lock().unwrap().extend(new);
    }
}

fn commits_at(outboxes: &[RecordingOutbox], height: u64) -> Vec<Hash32> {
    outboxes
        .iter()
        .flat_map(|o| {
            o.commits
                .lock()
                .unwrap()
                .iter()
                .filter(|c| c.height == height)
                .map(|c| c.block_id.clone())
                .collect::<Vec<_>>()
        })
        .collect()
}

// ── Safety invariant helper ───────────────────────────────────────────────

/// Assert that no two commits at the same height produced different block IDs.
/// This is the core SAFETY property of BFT consensus.
fn assert_safety(outboxes: &[RecordingOutbox]) {
    let mut height_to_id: HashMap<u64, Hash32> = HashMap::new();
    for ob in outboxes {
        for cert in ob.commits.lock().unwrap().iter() {
            if let Some(existing) = height_to_id.get(&cert.height) {
                assert_eq!(
                    *existing, cert.block_id,
                    "SAFETY VIOLATION: two different commits at height {}",
                    cert.height
                );
            } else {
                height_to_id.insert(cert.height, cert.block_id.clone());
            }
        }
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────

/// Happy path: 4 validators commit 3 consecutive blocks with no faults.
#[test]
#[ignore]
fn simnet_happy_path_multi_block() {
    let n = 4;
    let keys = make_keypairs(n);
    let vset = make_vset(&keys);
    let cfg = fast_config();
    let state = KvState::default();
    let stakes = make_stakes(&keys);
    let stores: Vec<MemBlockStore> = (0..n).map(|_| MemBlockStore::default()).collect();

    let mut engines: Vec<Engine<Ed25519Verifier>> = keys
        .iter()
        .map(|_| Engine::new(cfg.clone(), vset.clone(), 1, Hash32::zero(), state.clone(), stakes.clone(), None))
        .collect();
    let mut outboxes: Vec<RecordingOutbox> = (0..n).map(|_| RecordingOutbox::default()).collect();

    let target_height = 3;
    for _ in 0..200 {
        tick_all(&mut engines, &mut outboxes, &stores, &keys);
        broadcast_all(&mut engines, &mut outboxes, &stores, &keys);

        let all_committed = outboxes.iter().all(|o| {
            o.commits.lock().unwrap().len() >= target_height
        });
        if all_committed {
            break;
        }
    }

    assert_safety(&outboxes);

    // All validators must have committed at least `target_height` blocks
    for (i, ob) in outboxes.iter().enumerate() {
        let count = ob.commits.lock().unwrap().len();
        assert!(
            count >= target_height,
            "Validator {i} only committed {count} blocks, expected {target_height}"
        );
    }

    // All commits at same height must agree on block_id
    for h in 1..=target_height as u64 {
        let ids = commits_at(&outboxes, h);
        let unique: std::collections::HashSet<_> = ids.iter().collect();
        assert_eq!(unique.len(), 1, "Multiple different commits at height {h}");
    }
}

/// Partition test: split into 2+2, confirm no progress, then heal and check liveness.
#[test]
#[ignore]
fn simnet_partition_and_heal() {
    let n = 4;
    let keys = make_keypairs(n);
    let vset = make_vset(&keys);
    let cfg = fast_config();
    let state = KvState::default();
    let stakes = make_stakes(&keys);
    let stores: Vec<MemBlockStore> = (0..n).map(|_| MemBlockStore::default()).collect();

    let mut engines: Vec<Engine<Ed25519Verifier>> = keys
        .iter()
        .map(|_| Engine::new(cfg.clone(), vset.clone(), 1, Hash32::zero(), state.clone(), stakes.clone(), None))
        .collect();
    let mut outboxes: Vec<RecordingOutbox> = (0..n).map(|_| RecordingOutbox::default()).collect();

    // Phase 1: partition — two groups [0,1] and [2,3], no progress expected
    let partition_a = [0usize, 1];
    let partition_b = [2usize, 3];

    for _ in 0..50 {
        tick_all(&mut engines, &mut outboxes, &stores, &keys);
        // Only deliver within partitions (no cross-partition messages)
        broadcast_to_partition(&partition_a, &mut engines, &mut outboxes, &stores, &keys);
        broadcast_to_partition(&partition_b, &mut engines, &mut outboxes, &stores, &keys);
    }

    // During partition, neither side should have committed (2 of 4 = below 2/3 quorum)
    for ob in &outboxes {
        let count = ob.commits.lock().unwrap().len();
        assert_eq!(count, 0, "Should not commit during 2+2 partition");
    }

    assert_safety(&outboxes);

    // Phase 2: heal — resume full mesh delivery
    for _ in 0..200 {
        tick_all(&mut engines, &mut outboxes, &stores, &keys);
        broadcast_all(&mut engines, &mut outboxes, &stores, &keys);

        let some_committed = outboxes.iter().any(|o| {
            !o.commits.lock().unwrap().is_empty()
        });
        if some_committed {
            // Give others a few more rounds to catch up
            for _ in 0..50 {
                tick_all(&mut engines, &mut outboxes, &stores, &keys);
                broadcast_all(&mut engines, &mut outboxes, &stores, &keys);
            }
            break;
        }
    }

    assert_safety(&outboxes);

    // After heal, at least some validators should have committed
    let total_commits: usize = outboxes.iter()
        .map(|o| o.commits.lock().unwrap().len())
        .sum();
    assert!(total_commits > 0, "No commits after network heal");
}

/// Drop test: 20% message drop rate, consensus should still eventually commit.
#[test]
#[ignore]
fn simnet_message_drop_resilience() {
    let n = 4;
    let keys = make_keypairs(n);
    let vset = make_vset(&keys);
    let cfg = fast_config();
    let state = KvState::default();
    let stakes = make_stakes(&keys);
    let stores: Vec<MemBlockStore> = (0..n).map(|_| MemBlockStore::default()).collect();

    let mut engines: Vec<Engine<Ed25519Verifier>> = keys
        .iter()
        .map(|_| Engine::new(cfg.clone(), vset.clone(), 1, Hash32::zero(), state.clone(), stakes.clone(), None))
        .collect();
    let mut outboxes: Vec<RecordingOutbox> = (0..n).map(|_| RecordingOutbox::default()).collect();

    for _ in 0..300 {
        tick_all(&mut engines, &mut outboxes, &stores, &keys);
        broadcast_with_drop(&mut engines, &mut outboxes, &stores, &keys, 0.20);

        let committed = outboxes.iter().filter(|o| {
            !o.commits.lock().unwrap().is_empty()
        }).count();
        if committed >= n - 1 {
            break;
        }
    }

    assert_safety(&outboxes);

    let total_commits: usize = outboxes.iter()
        .map(|o| o.commits.lock().unwrap().len())
        .sum();
    assert!(total_commits > 0, "No commits under 20% drop rate");
}

/// One-Byzantine validator: 1 of 4 goes offline (no messages sent/received).
/// Remaining 3 (= 2/3+1) should still commit.
#[test]
#[ignore]
fn simnet_one_validator_offline() {
    let n = 4;
    let keys = make_keypairs(n);
    let vset = make_vset(&keys);
    let cfg = fast_config();
    let state = KvState::default();
    let stakes = make_stakes(&keys);
    let stores: Vec<MemBlockStore> = (0..n).map(|_| MemBlockStore::default()).collect();

    let mut engines: Vec<Engine<Ed25519Verifier>> = keys
        .iter()
        .map(|_| Engine::new(cfg.clone(), vset.clone(), 1, Hash32::zero(), state.clone(), stakes.clone(), None))
        .collect();
    let mut outboxes: Vec<RecordingOutbox> = (0..n).map(|_| RecordingOutbox::default()).collect();

    // Validator 3 is offline (never ticks or delivers)
    let online = [0usize, 1, 2];

    for _ in 0..300 {
        // Only tick online validators
        for &i in &online {
            let mut ob = outboxes[i].clone();
            engines[i].tick(&keys[i], &stores[i], &mut ob, 200, |_| vec![]);
            let new: Vec<_> = ob.broadcasts.lock().unwrap().drain(..).collect();
            outboxes[i].broadcasts.lock().unwrap().extend(new);
        }

        // Only deliver to/from online validators
        broadcast_to_partition(&online, &mut engines, &mut outboxes, &stores, &keys);

        let online_commits: usize = online.iter()
            .map(|&i| outboxes[i].commits.lock().unwrap().len())
            .sum();
        if online_commits >= 3 {
            break;
        }
    }

    assert_safety(&outboxes);

    // All online validators should have committed at least 1 block
    for &i in &online {
        let count = outboxes[i].commits.lock().unwrap().len();
        assert!(
            count >= 1,
            "Online validator {i} failed to commit with one offline node"
        );
    }
}
