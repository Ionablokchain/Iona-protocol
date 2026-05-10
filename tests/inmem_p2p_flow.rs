use iona::consensus::{
    BlockStore, Config, ConsensusMsg, Engine, Outbox, SimpleBlockProducer, SimpleProducerCfg, Step,
    Validator, ValidatorSet,
};
use iona::crypto::ed25519::{Ed25519Keypair, Ed25519Verifier};
use iona::crypto::Signer;
use iona::execution::KvState;
use iona::net::inmem::{InMemNet, NodeId};
use iona::slashing::StakeLedger;
use iona::types::{Block, Hash32};

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use tokio::sync::mpsc;

// -----------------------------------------------------------------------------
// Constants
// -----------------------------------------------------------------------------

const DEFAULT_SEED_1: u8 = 1;
const DEFAULT_SEED_2: u8 = 2;
const INITIAL_HEIGHT: u64 = 1;
const VALIDATOR_POWER: u64 = 1;
const NETWORK_DELAY_MS: u64 = 20;

// -----------------------------------------------------------------------------
// In-memory block store
// -----------------------------------------------------------------------------

#[derive(Default)]
struct MemStore {
    blocks: Mutex<HashMap<Hash32, Block>>,
}

impl BlockStore for MemStore {
    fn get(&self, id: &Hash32) -> Option<Block> {
        self.blocks.lock().ok()?.get(id).cloned()
    }

    fn put(&self, block: Block) {
        if let Ok(mut m) = self.blocks.lock() {
            m.insert(block.id(), block);
        }
    }
}

// -----------------------------------------------------------------------------
// In-memory outbox
// -----------------------------------------------------------------------------

/// Outbox that broadcasts over the in-memory network and records broadcasts for inspection.
struct InMemOutbox {
    net: InMemNet,
    pub broadcasts: Vec<ConsensusMsg>,
}

impl InMemOutbox {
    fn new(net: InMemNet) -> Self {
        Self {
            net,
            broadcasts: Vec::new(),
        }
    }
}

impl Outbox for InMemOutbox {
    fn broadcast(&mut self, msg: ConsensusMsg) {
        self.broadcasts.push(msg.clone());
        self.net.broadcast(msg);
    }

    fn request_block(&mut self, _block_id: Hash32) {}

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

// -----------------------------------------------------------------------------
// Helper: create a consensus engine
// -----------------------------------------------------------------------------

fn make_engine(height: u64, validator_set: ValidatorSet) -> Engine<Ed25519Verifier> {
    let mut config = Config::default();
    config.include_block_in_proposal = true;
    Engine::new(
        config,
        validator_set,
        height,
        Hash32::zero(),
        KvState::default(),
        StakeLedger::default(),
        None,
    )
}

// -----------------------------------------------------------------------------
// Helper: pump task to process incoming consensus messages
// -----------------------------------------------------------------------------

async fn pump(
    mut rx: mpsc::UnboundedReceiver<ConsensusMsg>,
    engine: Arc<tokio::sync::Mutex<Engine<Ed25519Verifier>>>,
    signer: Ed25519Keypair,
    store: Arc<MemStore>,
    outbox: Arc<tokio::sync::Mutex<InMemOutbox>>,
) {
    while let Some(msg) = rx.recv().await {
        let mut eng = engine.lock().await;
        let mut ob = outbox.lock().await;
        let _ = eng.on_message(&signer, store.as_ref(), &mut *ob, msg);
    }
}

// -----------------------------------------------------------------------------
// Test: in-memory network delivers proposal to observer
// -----------------------------------------------------------------------------

#[tokio::test]
async fn inmem_network_delivers_proposal_to_observer() {
    // ----- Validator setup -----
    let keypair1 = Ed25519Keypair::from_seed([DEFAULT_SEED_1; 32]);
    let keypair2 = Ed25519Keypair::from_seed([DEFAULT_SEED_2; 32]);

    let validator_set = ValidatorSet {
        vals: vec![
            Validator {
                pk: keypair1.public_key(),
                power: VALIDATOR_POWER,
            },
            Validator {
                pk: keypair2.public_key(),
                power: VALIDATOR_POWER,
            },
        ],
    };

    // ----- Network setup -----
    let (network1, rx1) = InMemNet::new(1u64.into());
    let rx2 = network1.register(2u64.into());
    let network2 = network1.handle(2u64.into());

    // ----- Node 1 (proposer) components -----
    let store1 = Arc::new(MemStore::default());
    let engine1 = Arc::new(tokio::sync::Mutex::new(make_engine(INITIAL_HEIGHT, validator_set.clone())));
    let outbox1 = Arc::new(tokio::sync::Mutex::new(InMemOutbox::new(network1.clone())));

    // ----- Node 2 (observer) components -----
    let store2 = Arc::new(MemStore::default());
    let engine2 = Arc::new(tokio::sync::Mutex::new(make_engine(INITIAL_HEIGHT, validator_set.clone())));
    let outbox2 = Arc::new(tokio::sync::Mutex::new(InMemOutbox::new(network2.clone())));

    // ----- Start message pumps -----
    let pump1 = tokio::spawn(pump(
        rx1,
        engine1.clone(),
        keypair1.clone(),
        store1.clone(),
        outbox1.clone(),
    ));
    let pump2 = tokio::spawn(pump(
        rx2,
        engine2.clone(),
        keypair1.clone(),
        store2.clone(),
        outbox2.clone(),
    ));

    // ----- Propose a block -----
    let producer = SimpleBlockProducer::new(SimpleProducerCfg {
        max_txs: 0,
        include_block_in_proposal: true,
    });

    {
        let mut engine = engine1.lock().await;
        assert_eq!(engine.state.step, Step::Propose);
        let mut outbox = outbox1.lock().await;
        let produced = producer.try_produce(
            &mut *engine,
            &keypair2,   // Producer should be validator 2 (index 1 at height 1, round 0)
            store1.as_ref(),
            &mut *outbox,
            vec![],
        );
        assert!(produced, "producer should have created a proposal");
    }

    // ----- Wait for message delivery -----
    tokio::time::sleep(std::time::Duration::from_millis(NETWORK_DELAY_MS)).await;

    // ----- Verify that observer received the proposal -----
    {
        let engine = engine2.lock().await;
        assert!(
            engine.state.proposal.is_some(),
            "observer should have received the proposal"
        );
    }

    // ----- Clean up -----
    pump1.abort();
    pump2.abort();
}
