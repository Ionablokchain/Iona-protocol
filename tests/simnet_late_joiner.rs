//! Test that a late‑joining node can receive a replayed proposal (via consensus history)
//! and then fetch the missing block, even under consensus message loss.

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

/// Node IDs.
const NODE_PRODUCER: NodeId = 1;
const NODE_OBSERVER: NodeId = 2;
const NODE_LATE_JOINER: NodeId = 3;

/// Validator seeds.
const SEED_VALIDATOR_1: u8 = 1;
const SEED_VALIDATOR_2: u8 = 2;

/// Initial consensus height.
const INITIAL_HEIGHT: u64 = 1;

/// Initial round.
const INITIAL_ROUND: u32 = 0;

/// Power of each validator.
const VALIDATOR_POWER: u64 = 1;

/// Drop probability for consensus messages (30%).
const DROP_PPM_CONSENSUS: u32 = 300_000; // 30% drop
const DROP_PPM_BLOCK: u32 = 0; // Reliable block traffic

/// Min/max delay for messages (milliseconds).
const MIN_DELAY_MS: u64 = 0;
const MAX_DELAY_MS: u64 = 25;

/// History limit for replay.
const HISTORY_LIMIT: usize = 64;

/// Seed for deterministic drop.
const NETWORK_SEED: u64 = 0x1234_5678_9ABC_DEF0;

/// Number of replay attempts to ensure the late joiner receives the proposal.
const REPLAY_ATTEMPTS: usize = 10;

/// Sleep duration between replay attempts (milliseconds).
const REPLAY_SLEEP_MS: u64 = 30;

/// Delay after replay to allow block request/response (milliseconds).
const BLOCK_FETCH_DELAY_MS: u64 = 80;

// -----------------------------------------------------------------------------
// Helpers
// -----------------------------------------------------------------------------

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
        self.net.request_block(block_id);
    }
    fn on_commit(
        &mut self,
        _cert: &iona::consensus::CommitCertificate,
        _block: &Block,
        _new_state: &KvState,
        _new_base_fee: u64,
        _receipts: &[iona::types::Receipt],
    ) {
    }
}

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

/// Wait until a node's engine has a proposal (timeout not used here, we poll).
async fn wait_for_proposal(
    engine: &Arc<tokio::sync::Mutex<Engine<Ed25519Verifier>>>,
    max_attempts: usize,
    sleep_ms: u64,
) -> bool {
    for _ in 0..max_attempts {
        if engine.lock().await.state.proposal.is_some() {
            return true;
        }
        tokio::time::sleep(std::time::Duration::from_millis(sleep_ms)).await;
    }
    false
}

// -----------------------------------------------------------------------------
// Test
// -----------------------------------------------------------------------------

#[tokio::test]
async fn late_joiner_receives_replayed_proposal_and_fetches_block_under_loss() {
    // --- 1. Create keypairs and validator set ---------------------------------
    let k1 = Ed25519Keypair::from_seed([SEED_VALIDATOR_1; 32]);
    let k2 = Ed25519Keypair::from_seed([SEED_VALIDATOR_2; 32]);

    let vset = ValidatorSet {
        vals: vec![
            Validator {
                pk: k1.public_key(),
                power: VALIDATOR_POWER,
            },
            Validator {
                pk: k2.public_key(),
                power: VALIDATOR_POWER,
            },
        ],
    };

    // --- 2. Configure simulated network ---------------------------------------
    let config = SimNetConfig {
        drop_ppm_consensus: DROP_PPM_CONSENSUS,
        drop_ppm_block: DROP_PPM_BLOCK,
        min_delay_ms: MIN_DELAY_MS,
        max_delay_ms: MAX_DELAY_MS,
        history_limit: HISTORY_LIMIT,
        seed: NETWORK_SEED,
    };

    // --- 3. Create network for the initial two nodes --------------------------
    let (net1, rx1) = SimNet::with_config(NODE_PRODUCER, config.clone());
    let rx2 = net1.register(NODE_OBSERVER);
    let net2 = net1.handle(NODE_OBSERVER);

    let store1 = Arc::new(MemStore::default());
    let store2 = Arc::new(MemStore::default());
    let eng1 = Arc::new(tokio::sync::Mutex::new(make_engine(INITIAL_HEIGHT, vset.clone(), false)));
    let eng2 = Arc::new(tokio::sync::Mutex::new(make_engine(INITIAL_HEIGHT, vset.clone(), false)));
    let out1 = Arc::new(tokio::sync::Mutex::new(SimOutbox::new(net1.clone())));
    let out2 = Arc::new(tokio::sync::Mutex::new(SimOutbox::new(net2.clone())));

    // --- 4. Spawn pumps for initial nodes -------------------------------------
    let pump1 = tokio::spawn(pump(
        rx1,
        eng1.clone(),
        k1.clone(),
        store1.clone(),
        out1.clone(),
        net1.clone(),
        NODE_PRODUCER,
    ));
    let pump2 = tokio::spawn(pump(
        rx2,
        eng2.clone(),
        k1.clone(),
        store2.clone(),
        out2.clone(),
        net2.clone(),
        NODE_OBSERVER,
    ));

    // --- 5. Produce a block using the producer node --------------------------
    // At height=1, round=0, proposer is validator #2 (k2) because round‑robin.
    let producer = SimpleBlockProducer::new(SimpleProducerCfg {
        max_txs: 0,
        include_block_in_proposal: false,
    });
    let block_id: Hash32;
    {
        let mut engine = eng1.lock().await;
        assert_eq!(engine.state.step, Step::Propose);
        let mut outbox = out1.lock().await;
        assert!(producer.try_produce(
            &mut *engine,
            &k2,
            store1.as_ref(),
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
            store1.get(&block_id).is_some(),
            "Producer must have the block"
        );
    }

    // --- 6. Late joiner registers after proposal broadcast --------------------
    let rx3 = net1.register(NODE_LATE_JOINER);
    let net3 = net1.handle(NODE_LATE_JOINER);
    let store3 = Arc::new(MemStore::default());
    let eng3 = Arc::new(tokio::sync::Mutex::new(make_engine(INITIAL_HEIGHT, vset.clone(), false)));
    let out3 = Arc::new(tokio::sync::Mutex::new(SimOutbox::new(net3.clone())));
    let pump3 = tokio::spawn(pump(
        rx3,
        eng3.clone(),
        k1.clone(),
        store3.clone(),
        out3.clone(),
        net3.clone(),
        NODE_LATE_JOINER,
    ));

    // --- 7. Replay consensus history to the late joiner -----------------------
    for _ in 0..REPLAY_ATTEMPTS {
        net1.replay_consensus_to(NODE_LATE_JOINER);
        tokio::time::sleep(std::time::Duration::from_millis(REPLAY_SLEEP_MS)).await;
        if eng3.lock().await.state.proposal.is_some() {
            break;
        }
    }

    // --- 8. Verify that the late joiner received a proposal -------------------
    assert!(
        eng3.lock().await.state.proposal.is_some(),
        "Late joiner should have received a proposal via replay"
    );

    // --- 9. Allow time for block request / response ---------------------------
    tokio::time::sleep(std::time::Duration::from_millis(BLOCK_FETCH_DELAY_MS)).await;

    // --- 10. Verify that the late joiner fetched the block --------------------
    assert!(
        store3.get(&block_id).is_some(),
        "Late joiner should have fetched the missing block"
    );

    // --- 11. Clean up ---------------------------------------------------------
    pump1.abort();
    pump2.abort();
    pump3.abort();
}
