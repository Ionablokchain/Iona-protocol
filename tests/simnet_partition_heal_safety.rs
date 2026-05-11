//! Test that after a network partition heals, all nodes converge on the same
//! proposal and no double proposals are produced for the same height and round.

use iona::consensus::{
    BlockStore, Config, ConsensusMsg, Engine, Outbox, SimpleBlockProducer, SimpleProducerCfg, Step,
    Validator, ValidatorSet,
};
use iona::crypto::ed25519::{Ed25519Keypair, Ed25519Verifier};
use iona::crypto::Signer;
use iona::execution::KvState;
use iona::net::simnet::{NetMsg, SimNet, SimNetConfig};
use iona::slashing::StakeLedger;
use iona::types::{Block, Hash32};

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use tokio::sync::mpsc;

// -----------------------------------------------------------------------------
// Constants
// -----------------------------------------------------------------------------

/// Number of validators in the test network.
const NUM_VALIDATORS: usize = 4;

/// Initial consensus height.
const INITIAL_HEIGHT: u64 = 1;

/// Round for the initial proposal.
const INITIAL_ROUND: u32 = 0;

/// Power assigned to each validator.
const VALIDATOR_POWER: u64 = 1;

/// Drop rates – none for this test.
const DROP_PPM_CONSENSUS: u32 = 0;
const DROP_PPM_BLOCK: u32 = 0;

/// Minimum and maximum message delay (ms).
const MIN_DELAY_MS: u64 = 0;
const MAX_DELAY_MS: u64 = 10;

/// History limit for network replay.
const HISTORY_LIMIT: usize = 64;

/// Seed for deterministic behaviour.
const NETWORK_SEED: u64 = 0xDEAD_BEEF_1111_2222;

/// Partition groups: validators 0‑1 in group 0, 2‑3 in group 1.
const PARTITION_GROUP_0: &[usize] = &[0, 1];
const PARTITION_GROUP_1: &[usize] = &[2, 3];

/// Interval for message propagation (ms).
const PROPAGATION_SLEEP_MS: u64 = 30;

/// Time to wait after healing for store synchronisation (ms).
const HEALING_SLEEP_MS: u64 = 80;

/// Number of replay attempts to ensure late‑joiners receive consensus history.
const REPLAY_ATTEMPTS: usize = 3;

// -----------------------------------------------------------------------------
// Helpers
// -----------------------------------------------------------------------------

/// In‑memory block store.
#[derive(Default)]
struct MemStore {
    blocks: Mutex<HashMap<Hash32, Block>>,
}

impl BlockStore for MemStore {
    fn get(&self, id: &Hash32) -> Option<Block> {
        self.blocks.lock().unwrap().get(id).cloned()
    }
    fn put(&self, block: Block) {
        let id = block.id();
        self.blocks.lock().unwrap().insert(id, block);
    }
}

/// Outbox that forwards messages to the simulated network.
struct SimOutbox {
    net: SimNet,
}

impl SimOutbox {
    fn new(net: SimNet) -> Self {
        Self { net }
    }
}

impl Outbox for SimOutbox {
    fn broadcast(&mut self, msg: ConsensusMsg) {
        self.net.broadcast_consensus(msg);
    }
    fn request_block(&mut self, block_id: Hash32) {
        self.net.request_block_with_retry(block_id, 6, 10);
    }
    fn on_commit(
        &mut self,
        _cert: &iona::consensus::CommitCertificate,
        _block: &Block,
        _new_state: &KvState,
        _new_base_fee: u64,
        _receipts: &[iona::types::Receipt],
    ) {
        // Not used in this test.
    }
}

/// Create a consensus engine with the given configuration.
fn make_engine(
    height: u64,
    vset: ValidatorSet,
    include_block_in_proposal: bool,
) -> Engine<Ed25519Verifier> {
    let mut cfg = Config::default();
    cfg.include_block_in_proposal = include_block_in_proposal;
    Engine::new(
        cfg,
        vset,
        height,
        Hash32::zero(),
        KvState::default(),
        StakeLedger::default(),
        None,
    )
}

/// Generate keypairs for the specified number of validators.
fn make_keypairs(n: usize) -> Vec<Ed25519Keypair> {
    (1..=n as u8)
        .map(|seed| Ed25519Keypair::from_seed([seed; 32]))
        .collect()
}

/// Create a validator set from a list of keypairs.
fn make_validator_set(keys: &[Ed25519Keypair]) -> ValidatorSet {
    ValidatorSet {
        vals: keys
            .iter()
            .map(|k| Validator {
                pk: k.public_key(),
                power: VALIDATOR_POWER,
            })
            .collect(),
    }
}

/// Background task that pumps network messages into a consensus engine.
async fn pump(
    mut rx: mpsc::UnboundedReceiver<NetMsg>,
    engine: Arc<tokio::sync::Mutex<Engine<Ed25519Verifier>>>,
    signer: Ed25519Keypair,
    store: Arc<MemStore>,
    outbox: Arc<tokio::sync::Mutex<SimOutbox>>,
    net: SimNet,
    node_id: u64,
) {
    while let Some(msg) = rx.recv().await {
        match msg {
            NetMsg::Consensus { from: _, msg } => {
                let mut eng = engine.lock().await;
                let mut ob = outbox.lock().await;
                let _ = eng.on_message(&signer, store.as_ref(), &mut *ob, msg);
            }
            NetMsg::BlockRequest { from, id } => {
                if let Some(block) = store.get(&id) {
                    net.send_to(
                        from,
                        NetMsg::BlockResponse {
                            from: node_id,
                            block,
                        },
                    );
                }
            }
            NetMsg::BlockResponse { from: _, block } => {
                store.put(block);
            }
        }
    }
}

// -----------------------------------------------------------------------------
// Test
// -----------------------------------------------------------------------------

#[tokio::test]
async fn partition_then_heal_converges_without_double_proposals() {
    // 1. Create keypairs and validator set.
    let keys = make_keypairs(NUM_VALIDATORS);
    let validator_set = make_validator_set(&keys);

    // 2. Configure the simulated network (no loss, small delay).
    let config = SimNetConfig {
        drop_ppm_consensus: DROP_PPM_CONSENSUS,
        drop_ppm_block: DROP_PPM_BLOCK,
        min_delay_ms: MIN_DELAY_MS,
        max_delay_ms: MAX_DELAY_MS,
        history_limit: HISTORY_LIMIT,
        seed: NETWORK_SEED,
    };

    // 3. Create the network and register all nodes.
    let (net1, rx1) = SimNet::with_config(1, config);
    let rx2 = net1.register(2);
    let rx3 = net1.register(3);
    let rx4 = net1.register(4);
    let net2 = net1.handle(2);
    let net3 = net1.handle(3);
    let net4 = net1.handle(4);

    // 4. Enable partitioning and assign nodes to groups.
    net1.enable_partitioning(true);
    for &node in PARTITION_GROUP_0 {
        net1.set_partition((node + 1) as u64, 0);
    }
    for &node in PARTITION_GROUP_1 {
        net1.set_partition((node + 1) as u64, 1);
    }

    // 5. Create per‑node stores, engines, and outboxes.
    let stores: Vec<Arc<MemStore>> = (0..NUM_VALIDATORS)
        .map(|_| Arc::new(MemStore::default()))
        .collect();
    let engines: Vec<Arc<tokio::sync::Mutex<Engine<Ed25519Verifier>>>> = (0..NUM_VALIDATORS)
        .map(|_| Arc::new(tokio::sync::Mutex::new(make_engine(
            INITIAL_HEIGHT,
            validator_set.clone(),
            false,
        ))))
        .collect();
    let outboxes: Vec<Arc<tokio::sync::Mutex<SimOutbox>>> = vec![
        Arc::new(tokio::sync::Mutex::new(SimOutbox::new(net1.clone()))),
        Arc::new(tokio::sync::Mutex::new(SimOutbox::new(net2.clone()))),
        Arc::new(tokio::sync::Mutex::new(SimOutbox::new(net3.clone()))),
        Arc::new(tokio::sync::Mutex::new(SimOutbox::new(net4.clone()))),
    ];

    // 6. Spawn background pumps.
    let pumps = vec![
        tokio::spawn(pump(
            rx1,
            engines[0].clone(),
            keys[0].clone(),
            stores[0].clone(),
            outboxes[0].clone(),
            net1.clone(),
            1,
        )),
        tokio::spawn(pump(
            rx2,
            engines[1].clone(),
            keys[0].clone(),
            stores[1].clone(),
            outboxes[1].clone(),
            net2.clone(),
            2,
        )),
        tokio::spawn(pump(
            rx3,
            engines[2].clone(),
            keys[0].clone(),
            stores[2].clone(),
            outboxes[2].clone(),
            net3.clone(),
            3,
        )),
        tokio::spawn(pump(
            rx4,
            engines[3].clone(),
            keys[0].clone(),
            stores[3].clone(),
            outboxes[3].clone(),
            net4.clone(),
            4,
        )),
    ];

    // 7. Produce a block using the first node’s engine.
    // The producer is validator #2 (index 1) because round‑robin at height 1, round 0.
    let producer = SimpleBlockProducer::new(SimpleProducerCfg {
        max_txs: 0,
        include_block_in_proposal: false, // light proposal
    });
    let block_id: Hash32;
    {
        let mut engine = engines[0].lock().await;
        assert_eq!(engine.state.step, Step::Propose);
        let mut outbox = outboxes[0].lock().await;
        assert!(producer.try_produce(
            &mut *engine,
            &keys[1],
            stores[0].as_ref(),
            &mut *outbox,
            vec![],
        ));
        block_id = engine
            .state
            .proposal
            .as_ref()
            .unwrap()
            .block_id
            .clone();
        assert!(
            stores[0].get(&block_id).is_some(),
            "Producer must have the block in its store"
        );
    }

    // 8. Partitioned nodes (indices 2 and 3) should NOT have the proposal yet.
    tokio::time::sleep(std::time::Duration::from_millis(PROPAGATION_SLEEP_MS)).await;
    assert!(
        engines[2].lock().await.state.proposal.is_none(),
        "Node 3 (index 2) received proposal while partitioned"
    );
    assert!(
        engines[3].lock().await.state.proposal.is_none(),
        "Node 4 (index 3) received proposal while partitioned"
    );

    // 9. Heal the partition and replay consensus history to the isolated nodes.
    net1.enable_partitioning(false);
    for _ in 0..REPLAY_ATTEMPTS {
        net1.replay_consensus_to(3);
        net1.replay_consensus_to(4);
        tokio::time::sleep(std::time::Duration::from_millis(PROPAGATION_SLEEP_MS)).await;
    }

    // 10. Allow time for block request/response and store synchronisation.
    tokio::time::sleep(std::time::Duration::from_millis(HEALING_SLEEP_MS)).await;

    // 11. Verify that all nodes now have the same proposal and the block in store.
    for i in 0..NUM_VALIDATORS {
        let engine_guard = engines[i].lock().await;
        let proposal = engine_guard
            .state
            .proposal
            .as_ref()
            .expect("Node should have a proposal after healing");
        assert_eq!(
            proposal.block_id, block_id,
            "Node {} has a different block ID",
            i + 1
        );
        assert!(
            stores[i].get(&block_id).is_some(),
            "Node {} does not have the block in its store",
            i + 1
        );
    }

    // 12. Safety: there must be exactly one proposal for height 1, round 0 in the
    // entire consensus history (no double proposal).
    let history = net1.consensus_history();
    let proposal_count = history
        .iter()
        .filter(|msg| {
            if let ConsensusMsg::Proposal(p) = msg {
                p.height == INITIAL_HEIGHT && p.round == INITIAL_ROUND
            } else {
                false
            }
        })
        .count();
    assert_eq!(
        proposal_count, 1,
        "Expected exactly one proposal for height={}, round={}, found {}",
        INITIAL_HEIGHT, INITIAL_ROUND, proposal_count
    );

    // 13. Clean up.
    for pump in pumps {
        pump.abort();
    }
}
