
use iona::consensus::{ConsensusMsg, SimpleBlockProducer, SimpleProducerCfg, Validator, ValidatorSet, BlockStore, Outbox, Engine, Step, Config};
use iona::crypto::ed25519::{Ed25519Keypair, Ed25519Verifier};
use iona::crypto::Signer;
use iona::types::{Hash32, Block};
use iona::slashing::StakeLedger;
use iona::execution::KvState;
use iona::net::inmem::{InMemNet, NodeId};

use std::collections::HashMap;
use std::sync::{Mutex, Arc};
use tokio::sync::mpsc;

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

/// Outbox that broadcasts over the in-memory network.
struct InMemOutbox {
    net: InMemNet,
    pub broadcasts: Vec<ConsensusMsg>,
}
impl InMemOutbox {
    fn new(net: InMemNet) -> Self { Self { net, broadcasts: vec![] } }
}
impl Outbox for InMemOutbox {
    fn broadcast(&mut self, msg: ConsensusMsg) {
        self.broadcasts.push(msg.clone());
        self.net.broadcast(msg);
    }
    fn request_block(&mut self, _block_id: Hash32) {}
    fn on_commit(&mut self, _cert: &iona::consensus::CommitCertificate, _block: &Block, _new_state: &KvState, _new_base_fee: u64, _receipts: &[iona::types::Receipt]) {}
}

fn make_engine(height: u64, vset: ValidatorSet) -> Engine<Ed25519Verifier> {
    let mut cfg = Config::default();
    cfg.include_block_in_proposal = true;
    Engine::new(cfg, vset, height, Hash32([0u8; 32]), KvState::default(), StakeLedger::default(), None)
}

async fn pump(
    mut rx: mpsc::UnboundedReceiver<ConsensusMsg>,
    engine: Arc<tokio::sync::Mutex<Engine<Ed25519Verifier>>>,
    signer: Ed25519Keypair,
    store: Arc<MemStore>,
    out: Arc<tokio::sync::Mutex<InMemOutbox>>,
) {
    while let Some(msg) = rx.recv().await {
        let mut eng = engine.lock().await;
        let mut ob = out.lock().await;
        let _ = eng.on_message(&signer, store.as_ref(), &mut *ob, msg);
    }
}

#[tokio::test]
async fn inmem_network_delivers_proposal_to_observer() {
    // Two validators
    let k1 = Ed25519Keypair::from_seed([1u8; 32]);
    let k2 = Ed25519Keypair::from_seed([2u8; 32]);

    let vset = ValidatorSet { vals: vec![
        Validator { pk: k1.public_key(), power: 1 },
        Validator { pk: k2.public_key(), power: 1 },
    ]};

    // Setup in-memory network with node ids
    let (net1, rx1) = InMemNet::new(1 as NodeId);
    let rx2 = net1.register(2 as NodeId);
    let net2 = net1.handle(2 as NodeId);

    // Node engines/stores/outboxes
    let store1 = Arc::new(MemStore::default());
    let store2 = Arc::new(MemStore::default());
    let eng1 = Arc::new(tokio::sync::Mutex::new(make_engine(1, vset.clone())));
    let eng2 = Arc::new(tokio::sync::Mutex::new(make_engine(1, vset.clone())));
    let out1 = Arc::new(tokio::sync::Mutex::new(InMemOutbox::new(net1.clone())));
    let out2 = Arc::new(tokio::sync::Mutex::new(InMemOutbox::new(net2.clone())));

    // Start pumps
    let p1 = tokio::spawn(pump(rx1, eng1.clone(), k1.clone(), store1.clone(), out1.clone()));
    let p2 = tokio::spawn(pump(rx2, eng2.clone(), k1.clone(), store2.clone(), out2.clone()));

    // Producer should be k2 at height=1 round=0 => idx=(1+0)%2=1
    let producer = SimpleBlockProducer::new(SimpleProducerCfg { max_txs: 0, include_block_in_proposal: true });
    {
        let mut eng = eng1.lock().await;
        assert_eq!(eng.state.step, Step::Propose);
        let mut ob = out1.lock().await;
        assert!(producer.try_produce(&mut *eng, &k2, store1.as_ref(), &mut *ob, vec![]));
    }

    // Give a moment for message delivery
    tokio::time::sleep(std::time::Duration::from_millis(20)).await;

    // Observer should have proposal now
    {
        let eng = eng2.lock().await;
        assert!(eng.state.proposal.is_some(), "observer should store proposal");
    }

    // Stop pumps
    p1.abort();
    p2.abort();
}
