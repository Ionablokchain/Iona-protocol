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
use std::hash::{Hash, Hasher};
use std::sync::{Arc, Mutex};

// -----------------------------------------------------------------------------
// Constants
// -----------------------------------------------------------------------------

/// Default number of validators in tests.
const DEFAULT_NUM_VALIDATORS: usize = 4;

/// Maximum rounds before giving up.
const DEFAULT_MAX_ROUNDS: u64 = 10;

/// Timeout values for fast configuration (milliseconds).
const PROPOSE_TIMEOUT_MS: u64 = 5000;
const PREVOTE_TIMEOUT_MS: u64 = 5000;
const PRECOMMIT_TIMEOUT_MS: u64 = 5000;

/// Tick duration in milliseconds.
const TICK_DURATION_MS: u64 = 200;

/// Gas target for tests.
const GAS_TARGET: u64 = 1_000_000;

/// Initial base fee per gas.
const INITIAL_BASE_FEE: u64 = 1;

/// Target block height for happy path test.
const TARGET_HEIGHT: u64 = 3;

/// Maximum number of iterations for consensus loops.
const MAX_ITERATIONS: usize = 300;

/// Number of iterations for partition test before healing.
const PARTITION_ITERATIONS: usize = 50;

/// Number of catch‑up rounds after healing.
const CATCHUP_ROUNDS: usize = 50;

/// Drop probability (0.0 – 1.0) for drop test.
const DROP_PROBABILITY: f64 = 0.20;

/// Number of validators online in the offline‑one test.
const ONLINE_VALIDATOR_INDICES: &[usize] = &[0, 1, 2];

/// Maximum height to attempt in happy path test.
const HAPPY_PATH_MAX_ITERATIONS: usize = 200;

// -----------------------------------------------------------------------------
// Shared in‑memory block store
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
// Recording outbox
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
// Simulation harness
// -----------------------------------------------------------------------------

/// A harness for running simulated consensus networks.
struct SimNet {
    keys: Vec<Ed25519Keypair>,
    stores: Vec<MemBlockStore>,
    engines: Vec<Engine<Ed25519Verifier>>,
    outboxes: Vec<RecordingOutbox>,
    config: Config,
    validator_set: ValidatorSet,
    stakes: StakeLedger,
    genesis_state: KvState,
}

impl SimNet {
    /// Create a new simulation network with `n` validators.
    fn new(n: usize) -> Self {
        let keys = make_keypairs(n);
        let validator_set = make_validator_set(&keys);
        let config = fast_config();
        let genesis_state = KvState::default();
        let stakes = make_stake_ledger(&keys);
        let stores = (0..n).map(|_| MemBlockStore::default()).collect();
        let engines = keys
            .iter()
            .map(|_| {
                Engine::new(
                    config.clone(),
                    validator_set.clone(),
                    1,
                    Hash32::zero(),
                    genesis_state.clone(),
                    stakes.clone(),
                    None,
                )
            })
            .collect();
        let outboxes = (0..n).map(|_| RecordingOutbox::default()).collect();

        Self {
            keys,
            stores,
            engines,
            outboxes,
            config,
            validator_set,
            stakes,
            genesis_state,
        }
    }

    /// Tick all engines once.
    fn tick_all(&mut self) {
        for i in 0..self.engines.len() {
            let mut ob = self.outboxes[i].clone();
            self.engines[i].tick(&self.keys[i], &self.stores[i], &mut ob, TICK_DURATION_MS, |_| vec![]);
            let new = ob.broadcasts.lock().unwrap().drain(..).collect::<Vec<_>>();
            self.outboxes[i].broadcasts.lock().unwrap().extend(new);
        }
    }

    /// Collect all pending broadcasts from all outboxes.
    fn collect_pending_messages(&mut self) -> Vec<ConsensusMsg> {
        self.outboxes
            .iter_mut()
            .flat_map(|ob| ob.broadcasts.lock().unwrap().drain(..).collect::<Vec<_>>())
            .collect()
    }

    /// Deliver a collection of messages to all engines (full mesh).
    fn deliver_to_all(&mut self, messages: &[ConsensusMsg]) {
        for (i, engine) in self.engines.iter_mut().enumerate() {
            for msg in messages {
                let mut ob = self.outboxes[i].clone();
                let _ = engine.on_message(&self.keys[i], &self.stores[i], &mut ob, msg.clone());
            }
        }
    }

    /// Deliver a collection of messages to a specific set of validators (by index).
    fn deliver_to_subset(&mut self, indices: &[usize], messages: &[ConsensusMsg]) {
        for &i in indices {
            if i >= self.engines.len() {
                continue;
            }
            for msg in messages {
                let mut ob = self.outboxes[i].clone();
                let _ = self.engines[i].on_message(&self.keys[i], &self.stores[i], &mut ob, msg.clone());
            }
        }
    }

    /// Full mesh broadcast of all pending messages.
    fn broadcast_all(&mut self) {
        let msgs = self.collect_pending_messages();
        self.deliver_to_all(&msgs);
    }

    /// Broadcast with a drop probability (deterministic pseudo‑random based on (i, j)).
    fn broadcast_with_drop(&mut self, drop_prob: f64) {
        let msgs = self.collect_pending_messages();
        for (i, engine) in self.engines.iter_mut().enumerate() {
            for (j, msg) in msgs.iter().enumerate() {
                let mut hasher = std::collections::hash_map::DefaultHasher::new();
                (i as u64 * 10000 + j as u64).hash(&mut hasher);
                let hash_val = hasher.finish();
                let frac = (hash_val % 10000) as f64 / 10000.0;
                if frac < drop_prob {
                    continue; // drop this message
                }
                let mut ob = self.outboxes[i].clone();
                let _ = engine.on_message(&self.keys[i], &self.stores[i], &mut ob, msg.clone());
            }
        }
    }

    /// Deliver pending messages only to a given set of validators (partition).
    fn broadcast_to_partition(&mut self, indices: &[usize]) {
        let msgs = self.collect_pending_messages();
        self.deliver_to_subset(indices, &msgs);
    }

    /// Get the number of commits recorded by each outbox.
    fn commit_counts(&self) -> Vec<usize> {
        self.outboxes
            .iter()
            .map(|ob| ob.commits.lock().unwrap().len())
            .collect()
    }

    /// Check if all validators have committed at least `target_height` blocks.
    fn all_committed_at_least(&self, target_height: usize) -> bool {
        self.outboxes
            .iter()
            .all(|ob| ob.commits.lock().unwrap().len() >= target_height)
    }

    /// Get all commits at a given height (list of block IDs).
    fn commits_at_height(&self, height: u64) -> Vec<Hash32> {
        self.outboxes
            .iter()
            .flat_map(|ob| {
                ob.commits
                    .lock()
                    .unwrap()
                    .iter()
                    .filter(|c| c.height == height)
                    .map(|c| c.block_id.clone())
                    .collect::<Vec<_>>()
            })
            .collect()
    }

    /// Assert the safety invariant: no two different commits at the same height.
    fn assert_safety(&self) {
        let mut height_to_id: HashMap<u64, Hash32> = HashMap::new();
        for ob in &self.outboxes {
            for cert in ob.commits.lock().unwrap().iter() {
                if let Some(existing) = height_to_id.get(&cert.height) {
                    assert_eq!(
                        *existing, cert.block_id,
                        "SAFETY VIOLATION: two different commits at height {}",
                        cert.height
                    );
                } else {
                    height_to_id.insert(cert.height, cert.block_id);
                }
            }
        }
    }
}

// -----------------------------------------------------------------------------
// Test helpers (standalone functions)
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

/// Create a validator set from the given keypairs.
fn make_validator_set(keys: &[Ed25519Keypair]) -> ValidatorSet {
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

/// Create a stake ledger for the given validators.
fn make_stake_ledger(keys: &[Ed25519Keypair]) -> StakeLedger {
    StakeLedger::default_demo_with(
        &keys.iter().map(|k| k.public_key()).collect::<Vec<_>>(),
        100,
    )
}

/// Fast consensus configuration for tests.
fn fast_config() -> Config {
    Config {
        propose_timeout_ms: PROPOSE_TIMEOUT_MS,
        prevote_timeout_ms: PREVOTE_TIMEOUT_MS,
        precommit_timeout_ms: PRECOMMIT_TIMEOUT_MS,
        max_rounds: DEFAULT_MAX_ROUNDS,
        max_txs_per_block: 100,
        gas_target: GAS_TARGET,
        initial_base_fee_per_gas: INITIAL_BASE_FEE,
        include_block_in_proposal: true,
        fast_quorum: true,
    }
}

/// Require that all commits at a given height agree on the same block ID.
fn assert_commits_agree_at_height(sim: &SimNet, height: u64) {
    let ids = sim.commits_at_height(height);
    let unique: std::collections::HashSet<_> = ids.iter().collect();
    assert_eq!(unique.len(), 1, "Conflicting commits at height {height}");
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

/// Happy path: 4 validators commit 3 consecutive blocks with no faults.
#[test]
#[ignore]
fn simnet_happy_path_multi_block() {
    let mut sim = SimNet::new(DEFAULT_NUM_VALIDATORS);

    for _ in 0..HAPPY_PATH_MAX_ITERATIONS {
        sim.tick_all();
        sim.broadcast_all();

        if sim.all_committed_at_least(TARGET_HEIGHT as usize) {
            break;
        }
    }

    sim.assert_safety();

    for i in 0..DEFAULT_NUM_VALIDATORS {
        let count = sim.commit_counts()[i];
        assert!(
            count >= TARGET_HEIGHT as usize,
            "Validator {i} committed {count} blocks, expected at least {TARGET_HEIGHT}"
        );
    }

    for h in 1..=TARGET_HEIGHT {
        assert_commits_agree_at_height(&sim, h);
    }
}

/// Partition test: split into 2+2, confirm no progress, then heal and check liveness.
#[test]
#[ignore]
fn simnet_partition_and_heal() {
    let mut sim = SimNet::new(DEFAULT_NUM_VALIDATORS);
    let partition_a = &[0, 1];
    let partition_b = &[2, 3];

    // Phase 1: partition – no cross‑partition messages
    for _ in 0..PARTITION_ITERATIONS {
        sim.tick_all();
        sim.broadcast_to_partition(partition_a);
        sim.broadcast_to_partition(partition_b);
    }

    // During partition, neither side should have committed (2 of 4 < 2/3)
    for count in sim.commit_counts() {
        assert_eq!(count, 0, "Should not commit during 2+2 partition");
    }
    sim.assert_safety();

    // Phase 2: heal – resume full mesh delivery
    for _ in 0..MAX_ITERATIONS {
        sim.tick_all();
        sim.broadcast_all();
        if sim.commit_counts().iter().any(|&c| c > 0) {
            // Give others a few more rounds to catch up
            for _ in 0..CATCHUP_ROUNDS {
                sim.tick_all();
                sim.broadcast_all();
            }
            break;
        }
    }

    sim.assert_safety();
    let total_commits: usize = sim.commit_counts().iter().sum();
    assert!(total_commits > 0, "No commits after network heal");
}

/// Drop test: 20% message drop rate, consensus should still eventually commit.
#[test]
#[ignore]
fn simnet_message_drop_resilience() {
    let mut sim = SimNet::new(DEFAULT_NUM_VALIDATORS);

    for _ in 0..MAX_ITERATIONS {
        sim.tick_all();
        sim.broadcast_with_drop(DROP_PROBABILITY);

        let online_commits = sim.commit_counts().iter().filter(|&&c| c > 0).count();
        if online_commits >= DEFAULT_NUM_VALIDATORS - 1 {
            break;
        }
    }

    sim.assert_safety();
    let total_commits: usize = sim.commit_counts().iter().sum();
    assert!(total_commits > 0, "No commits under 20% drop rate");
}

/// One-Byzantine validator: 1 of 4 goes offline (no messages sent/received).
/// Remaining 3 (= 2/3+1) should still commit.
#[test]
#[ignore]
fn simnet_one_validator_offline() {
    let mut sim = SimNet::new(DEFAULT_NUM_VALIDATORS);
    let online = ONLINE_VALIDATOR_INDICES;

    for _ in 0..MAX_ITERATIONS {
        // Only tick online validators
        for &i in online {
            let mut ob = sim.outboxes[i].clone();
            sim.engines[i].tick(&sim.keys[i], &sim.stores[i], &mut ob, TICK_DURATION_MS, |_| vec![]);
            let new = ob.broadcasts.lock().unwrap().drain(..).collect::<Vec<_>>();
            sim.outboxes[i].broadcasts.lock().unwrap().extend(new);
        }
        // Deliver messages only among online validators
        let msgs = sim.collect_pending_messages();
        sim.deliver_to_subset(online, &msgs);

        let online_commits: usize = online
            .iter()
            .map(|&i| sim.outboxes[i].commits.lock().unwrap().len())
            .sum();
        if online_commits >= 3 {
            break;
        }
    }

    sim.assert_safety();

    for &i in online {
        let count = sim.outboxes[i].commits.lock().unwrap().len();
        assert!(
            count >= 1,
            "Online validator {i} failed to commit with one offline node"
        );
    }
}
