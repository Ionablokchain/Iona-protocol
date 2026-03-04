
use iona::consensus::{ConsensusMsg, SimpleBlockProducer, SimpleProducerCfg, Validator, ValidatorSet, BlockStore, Outbox, Engine, Step, Config};
use iona::crypto::ed25519::{Ed25519Keypair, Ed25519Verifier};
use iona::crypto::Signer;
use iona::types::{Hash32, Block};
use iona::slashing::StakeLedger;
use iona::execution::KvState;
use iona::net::simnet::{SimNet, NetMsg, SimNetConfig};

use std::collections::HashMap;
use std::sync::{Mutex, Arc};
use tokio::sync::mpsc;

#[derive(Default)]
struct MemStore {
    blocks: Mutex<HashMap<Hash32, Block>>,
}
impl BlockStore for MemStore {
    fn get(&self, id: &Hash32) -> Option<Block> { self.blocks.lock().ok()?.get(id).cloned() }
    fn put(&self, block: Block) { if let Ok(mut m) = self.blocks.lock() { m.insert(block.id(), block); } }
}

struct SimOutbox { net: SimNet }
impl SimOutbox { fn new(net: SimNet) -> Self { Self { net } } }
impl Outbox for SimOutbox {
    fn broadcast(&mut self, msg: ConsensusMsg) { self.net.broadcast_consensus(msg); }
    fn request_block(&mut self, block_id: Hash32) { self.net.request_block_with_retry(block_id, 6, 10); }
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
    self_id: u64,
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
async fn partition_then_heal_converges_without_double_proposals() {
    let ks: Vec<Ed25519Keypair> = (1u8..=4u8).map(|i| Ed25519Keypair::from_seed([i; 32])).collect();
    let vset = ValidatorSet { vals: ks.iter().map(|k| Validator { pk: k.public_key(), power: 1 }).collect() };

    let cfg = SimNetConfig {
        drop_ppm_consensus: 0,
        drop_ppm_block: 0,
        min_delay_ms: 0,
        max_delay_ms: 10,
        history_limit: 64,
        seed: 0xDEAD_BEEF_1111_2222,
    };
    let (net1, rx1) = SimNet::with_config(1, cfg.clone());
    let rx2 = net1.register(2);
    let rx3 = net1.register(3);
    let rx4 = net1.register(4);
    let net2 = net1.handle(2);
    let net3 = net1.handle(3);
    let net4 = net1.handle(4);

    // Enable partitioning and split into {1,2} and {3,4}
    net1.enable_partitioning(true);
    net1.set_partition(1, 0); net1.set_partition(2, 0);
    net1.set_partition(3, 1); net1.set_partition(4, 1);

    let stores: Vec<Arc<MemStore>> = (0..4).map(|_| Arc::new(MemStore::default())).collect();
    let engines: Vec<Arc<tokio::sync::Mutex<Engine<Ed25519Verifier>>>> = (0..4).map(|_| Arc::new(tokio::sync::Mutex::new(make_engine(1, vset.clone(), false)))).collect();
    let outs: Vec<Arc<tokio::sync::Mutex<SimOutbox>>> = vec![
        Arc::new(tokio::sync::Mutex::new(SimOutbox::new(net1.clone()))),
        Arc::new(tokio::sync::Mutex::new(SimOutbox::new(net2.clone()))),
        Arc::new(tokio::sync::Mutex::new(SimOutbox::new(net3.clone()))),
        Arc::new(tokio::sync::Mutex::new(SimOutbox::new(net4.clone()))),
    ];

    let t1 = tokio::spawn(pump(rx1, engines[0].clone(), ks[0].clone(), stores[0].clone(), outs[0].clone(), net1.clone(), 1));
    let t2 = tokio::spawn(pump(rx2, engines[1].clone(), ks[0].clone(), stores[1].clone(), outs[1].clone(), net2.clone(), 2));
    let t3 = tokio::spawn(pump(rx3, engines[2].clone(), ks[0].clone(), stores[2].clone(), outs[2].clone(), net3.clone(), 3));
    let t4 = tokio::spawn(pump(rx4, engines[3].clone(), ks[0].clone(), stores[3].clone(), outs[3].clone(), net4.clone(), 4));

    // Producer is validator idx=(1+0)%4 = 1 => key #2, node 1 triggers producer logic
    let producer = SimpleBlockProducer::new(SimpleProducerCfg { max_txs: 0, include_block_in_proposal: false });

    let block_id: Hash32;
    {
        let mut eng = engines[0].lock().await;
        assert_eq!(eng.state.step, Step::Propose);
        let mut ob = outs[0].lock().await;
        assert!(producer.try_produce(&mut *eng, &ks[1], stores[0].as_ref(), &mut *ob, vec![]));
        block_id = eng.state.proposal.as_ref().unwrap().block_id.clone();
        assert!(stores[0].get(&block_id).is_some());
    }

    // Partitioned nodes (3,4) should NOT have proposal yet.
    tokio::time::sleep(std::time::Duration::from_millis(30)).await;
    assert!(engines[2].lock().await.state.proposal.is_none());
    assert!(engines[3].lock().await.state.proposal.is_none());

    // Heal partition and replay history to nodes 3 and 4.
    net1.enable_partitioning(false);
    for _ in 0..3 {
        net1.replay_consensus_to(3);
        net1.replay_consensus_to(4);
        tokio::time::sleep(std::time::Duration::from_millis(30)).await;
    }

    // Allow time for block request/response and store sync.
    tokio::time::sleep(std::time::Duration::from_millis(80)).await;

    // All nodes should now have the same proposal block_id and the block in store.
    for i in 0..4 {
        let eng = engines[i].lock().await;
        let pid = eng.state.proposal.as_ref().unwrap().block_id.clone();
        assert_eq!(pid, block_id);
        assert!(stores[i].get(&block_id).is_some());
    }

    // Safety: no double proposals for (height=1, round=0) in simnet history.
    let hist = net1.consensus_history();
    let mut proposals = 0;
    for m in hist {
        if let ConsensusMsg::Proposal(p) = m {
            if p.height == 1 && p.round == 0 { proposals += 1; }
        }
    }
    assert_eq!(proposals, 1, "expected exactly one proposal for height=1 round=0");

    t1.abort(); t2.abort(); t3.abort(); t4.abort();
}
