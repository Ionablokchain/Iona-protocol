//! Test that an observer correctly requests and receives a block when the proposal
//! does not contain the block (light proposal). This verifies the block request/response
//! mechanism in the `SimNet` simulation.

use iona::consensus::{
    BlockStore, Config, ConsensusMsg, Engine, Outbox, SimpleBlockProducer, SimpleProducerCfg, Step,
    Validator, ValidatorSet,
};
use iona::crypto::ed25519::{Ed25519Keypair, Ed25519Verifier};
use iona::crypto::Signer;
use iona::execution::KvState;
use iona::net::simnet::{NetMsg, NodeId, SimNet};
use iona::slashing::StakeLedger;
use iona::types::{Block, Hash32};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use tokio::sync::mpsc;

// -----------------------------------------------------------------------------
// Constants
// -----------------------------------------------------------------------------

/// Seed for the first validator (producer's key).
const SEED_VALIDATOR_1: u8 = 1;

/// Seed for the second validator (observer's key).
const SEED_VALIDATOR_2: u8 = 2;

/// Initial consensus height for the test.
const INITIAL_HEIGHT: u64 = 1;

/// Round in which the producer will propose.
const INITIAL_ROUND: u32 = 0;

/// Node ID for the first validator.
const NODE_ID_1: NodeId = 1;

/// Node ID for the second validator (observer).
const NODE_ID_2: NodeId = 2;

/// Small delay (ms) to allow message propagation in the simulation.
const MESSAGE_DELAY_MS: u64 = 40;

/// Power assigned to each validator in the test set.
const VALIDATOR_POWER: u64 = 1;

// -----------------------------------------------------------------------------
// Helper: in‑memory block store (shared state)
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
        if let Ok(mut map) = self.blocks.lock() {
            map.insert(block.id(), block);
        }
    }
}

// -----------------------------------------------------------------------------
// Outbox that forwards messages to the simulated network
// -----------------------------------------------------------------------------

struct SimOutbox {
    net: SimNet,
    broadcasts: Vec<ConsensusMsg>,
}

impl SimOutbox {
    fn new(net: SimNet) -> Self {
        Self {
            net,
            broadcasts: Vec::new(),
        }
    }
}

impl Outbox for SimOutbox {
    fn broadcast(&mut self, msg: ConsensusMsg) {
        self.broadcasts.push(msg.clone());
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
        // No action needed for this test.
    }
}

// -----------------------------------------------------------------------------
// Engine factory
// -----------------------------------------------------------------------------

fn make_engine(height: u64, vset: ValidatorSet, include_block_in_proposal: bool) -> Engine<Ed25519Verifier> {
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

// -----------------------------------------------------------------------------
// Background task to pump network messages into the consensus engine
// -----------------------------------------------------------------------------

async fn pump(
    mut rx: mpsc::UnboundedReceiver<NetMsg>,
    engine: Arc<tokio::sync::Mutex<Engine<Ed25519Verifier>>>,
    signer: Ed25519Keypair,
    store: Arc<MemStore>,
    outbox: Arc<tokio::sync::Mutex<SimOutbox>>,
    net: SimNet,
    self_id: NodeId,
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
                            from: self_id,
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
// Test: observer requests block when proposal is light (no block included)
// -----------------------------------------------------------------------------

#[tokio::test]
async fn observer_requests_and_receives_block_for_light_proposal() {
    // --- Setup: two validators -------------------------------------------------
    let k1 = Ed25519Keypair::from_seed([SEED_VALIDATOR_1; 32]);
    let k2 = Ed25519Keypair::from_seed([SEED_VALIDATOR_2; 32]);

    let validator_set = ValidatorSet {
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

    // --- Create simulated network ---------------------------------------------
    let (net1, rx1) = SimNet::new(NODE_ID_1);
    let rx2 = net1.register(NODE_ID_2);
    let net2 = net1.handle(NODE_ID_2);

    // --- Block stores ---------------------------------------------------------
    let store1 = Arc::new(MemStore::default());
    let store2 = Arc::new(MemStore::default());

    // --- Consensus engines ----------------------------------------------------
    let eng1 = Arc::new(tokio::sync::Mutex::new(make_engine(INITIAL_HEIGHT, validator_set.clone(), false)));
    let eng2 = Arc::new(tokio::sync::Mutex::new(make_engine(INITIAL_HEIGHT, validator_set.clone(), false)));

    // --- Outboxes -------------------------------------------------------------
    let out1 = Arc::new(tokio::sync::Mutex::new(SimOutbox::new(net1.clone())));
    let out2 = Arc::new(tokio::sync::Mutex::new(SimOutbox::new(net2.clone())));

    // --- Spawn background message pumps ---------------------------------------
    let pump1 = tokio::spawn(pump(
        rx1,
        eng1.clone(),
        k1.clone(),
        store1.clone(),
        out1.clone(),
        net1.clone(),
        NODE_ID_1,
    ));
    let pump2 = tokio::spawn(pump(
        rx2,
        eng2.clone(),
        k1.clone(),
        store2.clone(),
        out2.clone(),
        net2.clone(),
        NODE_ID_2,
    ));

    // --- Producer logic -------------------------------------------------------
    // At height = 1, round = 0, the proposer should be the second validator (k2)
    // because the set has two validators and the round-robin order starts at index 1.
    let producer = SimpleBlockProducer::new(SimpleProducerCfg {
        max_txs: 0,
        include_block_in_proposal: false, // light proposal – block not included
    });

    let block_id: Hash32;
    {
        let mut engine = eng1.lock().await;
        assert_eq!(engine.state.step, Step::Propose);
        let mut outbox = out1.lock().await;

        let produced = producer.try_produce(
            &mut *engine,
            &k2,
            store1.as_ref(),
            &mut *outbox,
            vec![],
        );
        assert!(produced, "producer should have created a proposal");

        let proposal = engine
            .state
            .proposal
            .as_ref()
            .expect("engine should have a proposal after production");
        block_id = proposal.block_id.clone();

        // Producer must have stored the block locally.
        assert!(
            store1.get(&block_id).is_some(),
            "producer must have the block in its block store"
        );
    }

    // --- Wait for message propagation -----------------------------------------
    tokio::time::sleep(std::time::Duration::from_millis(MESSAGE_DELAY_MS)).await;

    // --- Observer must now have the block -------------------------------------
    assert!(
        store2.get(&block_id).is_some(),
        "observer should have received the requested block"
    );

    // --- Clean up -------------------------------------------------------------
    pump1.abort();
    pump2.abort();
}
