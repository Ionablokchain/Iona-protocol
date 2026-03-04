
use iona::consensus::{ConsensusMsg, SimpleBlockProducer, SimpleProducerCfg, Validator, ValidatorSet, BlockStore, Outbox, Engine, Step, Config};
use iona::crypto::ed25519::{Ed25519Keypair, Ed25519Verifier};
use iona::crypto::Signer;
use iona::types::{Hash32, Block};
use iona::slashing::StakeLedger;
use iona::execution::KvState;
use iona::net::simnet::{SimNet, NetMsg, NodeId};

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

/// Outbox backed by SimNet.
struct SimOutbox {
    net: SimNet,
    pub broadcasts: Vec<ConsensusMsg>,
}
impl SimOutbox {
    fn new(net: SimNet) -> Self { Self { net, broadcasts: vec![] } }
}
impl Outbox for SimOutbox {
    fn broadcast(&mut self, msg: ConsensusMsg) {
        self.broadcasts.push(msg.clone());
        self.net.broadcast_consensus(msg);
    }
    fn request_block(&mut self, block_id: Hash32) {
        self.net.request_block(block_id);
    }
    fn on_commit(&mut self, _cert: &iona::consensus::CommitCertificate, _block: &Block, _new_state: &KvState, _new_base_fee: u64, _receipts: &[iona::types::Receipt]) {}
}

fn make_engine(height: u64, vset: ValidatorSet, include_block_in_proposal: bool) -> Engine<Ed25519Verifier> {
    let mut cfg = Config::default();
    cfg.include_block_in_proposal = include_block_in_proposal;
    Engine::new(cfg, vset, height, Hash32([0u8; 32]), KvState::default(), StakeLedger::default(), None)
}

async fn pump(
    mut rx: mpsc::UnboundedReceiver<NetMsg>,
    engine: Arc<tokio::sync::Mutex<Engine<Ed25519Verifier>>>,
    signer: Ed25519Keypair,
    store: Arc<MemStore>,
    out: Arc<tokio::sync::Mutex<SimOutbox>>,
    net: SimNet,
    self_id: NodeId,
) {
    while let Some(nm) = rx.recv().await {
        match nm {
            NetMsg::Consensus { from: _from, msg } => {
                let mut eng = engine.lock().await;
                let mut ob = out.lock().await;
                let _ = eng.on_message(&signer, store.as_ref(), &mut *ob, msg);
            }
            NetMsg::BlockRequest { from, id } => {
                if let Some(b) = store.get(&id) {
                    net.send_to(from, NetMsg::BlockResponse { from: self_id, block: b });
                }
            }
            NetMsg::BlockResponse { from: _from, block } => {
                store.put(block);
            }
        }
    }
}

#[tokio::test]
async fn observer_requests_and_receives_block_for_light_proposal() {
    // Two validators
    let k1 = Ed25519Keypair::from_seed([1u8; 32]);
    let k2 = Ed25519Keypair::from_seed([2u8; 32]);

    let vset = ValidatorSet { vals: vec![
        Validator { pk: k1.public_key(), power: 1 },
        Validator { pk: k2.public_key(), power: 1 },
    ]};

    // Setup simnet
    let (net1, rx1) = SimNet::new(1);
    let rx2 = net1.register(2);
    let net2 = net1.handle(2);

    // Producer includes NO block in proposal so observer must request it.
    let store1 = Arc::new(MemStore::default());
    let store2 = Arc::new(MemStore::default());
    let eng1 = Arc::new(tokio::sync::Mutex::new(make_engine(1, vset.clone(), false)));
    let eng2 = Arc::new(tokio::sync::Mutex::new(make_engine(1, vset.clone(), false)));
    let out1 = Arc::new(tokio::sync::Mutex::new(SimOutbox::new(net1.clone())));
    let out2 = Arc::new(tokio::sync::Mutex::new(SimOutbox::new(net2.clone())));

    let p1 = tokio::spawn(pump(rx1, eng1.clone(), k1.clone(), store1.clone(), out1.clone(), net1.clone(), 1));
    let p2 = tokio::spawn(pump(rx2, eng2.clone(), k1.clone(), store2.clone(), out2.clone(), net2.clone(), 2));

    // Producer should be k2 at height=1 round=0 => idx=(1+0)%2=1
    let producer = SimpleBlockProducer::new(SimpleProducerCfg { max_txs: 0, include_block_in_proposal: false });
    let block_id: Hash32;
    {
        let mut eng = eng1.lock().await;
        assert_eq!(eng.state.step, Step::Propose);
        let mut ob = out1.lock().await;
        assert!(producer.try_produce(&mut *eng, &k2, store1.as_ref(), &mut *ob, vec![]));
        block_id = eng.state.proposal.as_ref().unwrap().block_id.clone();
        assert!(store1.get(&block_id).is_some(), "producer must have the block");
    }

    // Give time for observer to receive proposal, request block, and then receive response.
    tokio::time::sleep(std::time::Duration::from_millis(40)).await;

    assert!(store2.get(&block_id).is_some(), "observer should receive requested block");

    p1.abort();
    p2.abort();
}
