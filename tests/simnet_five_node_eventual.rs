//! Test that under simulated network loss (message drop + delay), all 5 nodes
//! eventually receive a block, even when the proposal is light (block not included).

use iona::consensus::{
    BlockStore, Config, ConsensusMsg, Engine, Outbox, SimpleBlockProducer, SimpleProducerCfg, Step,
    Validator, ValidatorSet,
};
use iona::crypto::ed25519::{Ed25519Keypair, Ed25519Verifier};
use iona::crypto::Signer;
use iona::execution::KvState;
use iona::net::simnet::{NetMsg, NodeId, SimNet, SimNetConfig};
use iona::slashing::StakeLedger;
use iona::types::{Block, Hash32};

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use tokio::sync::mpsc;

// -----------------------------------------------------------------------------
// Constants
// -----------------------------------------------------------------------------

/// Number of validators in the test network.
const NUM_VALIDATORS: usize = 5;

/// Initial consensus height.
const INITIAL_HEIGHT: u64 = 1;

/// Round for the initial proposal.
const INITIAL_ROUND: u32 = 0;

/// Power assigned to each validator.
const VALIDATOR_POWER: u64 = 1;

/// Drop probability for consensus messages (ppm: parts per million).
const DROP_PPM_CONSENSUS: u32 = 150_000; // 15%

/// Drop probability for block messages (ppm).
const DROP_PPM_BLOCK: u32 = 150_000; // 15%

/// Minimum message delay (milliseconds).
const MIN_DELAY_MS: u64 = 0;

/// Maximum message delay (milliseconds).
const MAX_DELAY_MS: u64 = 20;

/// History limit for network replay.
const HISTORY_LIMIT: usize = 128;

/// Seed for deterministic random drops.
const NETWORK_SEED: u64 = 0xBEEF_1234_0000_7777;

/// Number of replay attempts for late‑joiner recovery.
const REPLAY_ATTEMPTS: usize = 12;

/// Duration (seconds) to wait for all nodes to receive the block.
const DEADLINE_SECS: u64 = 5;

/// Sleep duration between checks (milliseconds).
const CHECK_INTERVAL_MS: u64 = 40;

/// Sleep after each replay attempt (milliseconds).
const REPLAY_SLEEP_MS: u64 = 50;

// -----------------------------------------------------------------------------
// Helpers
// -----------------------------------------------------------------------------

/// In‑memory block store (shared state for a single node).
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
        // Use retry to tolerate block traffic loss.
        self.net.request_block_with_retry(block_id, 8, 10);
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
    node_id: NodeId,
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

/// Wait until all nodes have received the given block ID, or time out.
async fn wait_for_all_nodes(stores: &[Arc<MemStore>], block_id: &Hash32, deadline_secs: u64) {
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(deadline_secs);
    loop {
        let received = stores.iter().filter(|s| s.get(block_id).is_some()).count();
        if received == stores.len() {
            break;
        }
        if tokio::time::Instant::now() > deadline {
            panic!(
                "Not all nodes received the block by deadline: {}/{}",
                received,
                stores.len()
            );
        }
        tokio::time::sleep(std::time::Duration::from_millis(CHECK_INTERVAL_MS)).await;
    }
}

// -----------------------------------------------------------------------------
// Test
// -----------------------------------------------------------------------------

#[tokio::test]
async fn five_nodes_eventually_receive_block_under_loss() {
    // 1. Create keypairs and validator set.
    let keys = make_keypairs(NUM_VALIDATORS);
    let vset = make_validator_set(&keys);

    // 2. Configure the simulated network with loss and delay.
    let config = SimNetConfig {
        drop_ppm_consensus: DROP_PPM_CONSENSUS,
        drop_ppm_block: DROP_PPM_BLOCK,
        min_delay_ms: MIN_DELAY_MS,
        max_delay_ms: MAX_DELAY_MS,
        history_limit: HISTORY_LIMIT,
        seed: NETWORK_SEED,
    };

    // 3. Create the network and register all nodes.
    let (net1, rx1) = SimNet::with_config(NODE_ID_1, config);
    let mut receivers = vec![rx1];
    for node_id in 2..=NUM_VALIDATORS as NodeId {
        receivers.push(net1.register(node_id));
    }
    let network_handles: Vec<SimNet> = (1..=NUM_VALIDATORS as NodeId)
        .map(|node_id| net1.handle(node_id))
        .collect();

    // 4. Create per‑node stores, engines, and outboxes.
    let mut stores: Vec<Arc<MemStore>> = Vec::new();
    let mut engines: Vec<Arc<tokio::sync::Mutex<Engine<Ed25519Verifier>>>> = Vec::new();
    let mut outboxes: Vec<Arc<tokio::sync::Mutex<SimOutbox>>> = Vec::new();
    for _ in 0..NUM_VALIDATORS {
        stores.push(Arc::new(MemStore::default()));
        engines.push(Arc::new(tokio::sync::Mutex::new(make_engine(
            INITIAL_HEIGHT,
            vset.clone(),
            false,
        ))));
    }
    for i in 0..NUM_VALIDATORS {
        outboxes.push(Arc::new(tokio::sync::Mutex::new(SimOutbox::new(
            network_handles[i].clone(),
        ))));
    }

    // 5. Spawn background pumps for each node.
    let mut tasks = Vec::new();
    let mut rx_iter = receivers.into_iter();
    for i in 0..NUM_VALIDATORS {
        let rx = rx_iter.next().unwrap();
        let engine = engines[i].clone();
        let outbox = outboxes[i].clone();
        let net = network_handles[i].clone();
        let store = stores[i].clone();
        let signer = keys[i].clone();
        tasks.push(tokio::spawn(pump(
            rx,
            engine,
            signer,
            store,
            outbox,
            net,
            (i + 1) as NodeId,
        )));
    }

    // 6. Produce a block using the first node’s engine.
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

    // 7. Replay consensus history to late joiners several times to overcome drops.
    for _ in 0..REPLAY_ATTEMPTS {
        for node_id in 2..=NUM_VALIDATORS as NodeId {
            net1.replay_consensus_to(node_id);
        }
        tokio::time::sleep(std::time::Duration::from_millis(REPLAY_SLEEP_MS)).await;
    }

    // 8. Wait for all nodes to receive the block (with timeout).
    wait_for_all_nodes(&stores, &block_id, DEADLINE_SECS).await;

    // 9. Clean up.
    for task in tasks {
        task.abort();
    }
}
