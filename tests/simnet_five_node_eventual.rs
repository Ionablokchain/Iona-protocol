
use iona::consensus::{ConsensusMsg, SimpleBlockProducer, SimpleProducerCfg, Validator, ValidatorSet, BlockStore, Outbox, Engine, Step, Config};
use iona::crypto::ed25519::{Ed25519Keypair, Ed25519Verifier};
use iona::crypto::Signer;
use iona::types::{Hash32, Block};
use iona::slashing::StakeLedger;
use iona::execution::KvState;
use iona::net::simnet::{SimNet, NetMsg, NodeId, SimNetConfig};

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

struct SimOutbox {
    net: SimNet,
}
impl SimOutbox {
    fn new(net: SimNet) -> Self { Self { net } }
}
impl Outbox for SimOutbox {
    fn broadcast(&mut self, msg: ConsensusMsg) { self.net.broadcast_consensus(msg); }
    fn request_block(&mut self, block_id: Hash32) {
        // Use retry here to tolerate block traffic loss in this test.
        self.net.request_block_with_retry(block_id, 8, 10);
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
async fn five_nodes_eventually_receive_block_under_loss() {
    // 5 validators (keys)
    let ks: Vec<Ed25519Keypair> = (1u8..=5u8).map(|i| Ed25519Keypair::from_seed([i; 32])).collect();
    let vset = ValidatorSet {
        vals: ks.iter().map(|k| Validator { pk: k.public_key(), power: 1 }).collect(),
    };

    // Loss on BOTH consensus and block traffic (but not too extreme). Add delay.
    let cfg = SimNetConfig {
        drop_ppm_consensus: 150_000, // 15%
        drop_ppm_block: 150_000,     // 15%
        min_delay_ms: 0,
        max_delay_ms: 20,
        history_limit: 128,
        seed: 0xBEEF_1234_0000_7777,
    };

    let (net1, rx1) = SimNet::with_config(1, cfg.clone());
    let mut rxs = vec![rx1];
    for id in 2..=5 {
        rxs.push(net1.register(id));
    }
    let nets: Vec<SimNet> = (1..=5).map(|id| net1.handle(id)).collect();

    // Engines/stores/outboxes for nodes
    let mut stores: Vec<Arc<MemStore>> = Vec::new();
    let mut engines: Vec<Arc<tokio::sync::Mutex<Engine<Ed25519Verifier>>>> = Vec::new();
    let mut outboxes: Vec<Arc<tokio::sync::Mutex<SimOutbox>>> = Vec::new();
    for _ in 0..5 {
        stores.push(Arc::new(MemStore::default()));
        engines.push(Arc::new(tokio::sync::Mutex::new(make_engine(1, vset.clone(), false))));
    }
    for i in 0..5 {
        outboxes.push(Arc::new(tokio::sync::Mutex::new(SimOutbox::new(nets[i].clone()))));
    }

    // Spawn pumps
    let mut tasks = Vec::new();
    for i in 0..5 {
        let rx = rxs.remove(0);
        let eng_c = engines[i].clone();
        let out_c = outboxes[i].clone();
        let net = nets[i].clone();
        let store = stores[i].clone();
        let signer = ks[i].clone();
        tasks.push(tokio::spawn(pump(rx, eng_c, signer, store, out_c, net, (i+1) as u64)));
    }

    // Producer: use node1 engine, proposer determined by round-robin
    let producer = SimpleBlockProducer::new(SimpleProducerCfg { max_txs: 0, include_block_in_proposal: false });
    let block_id: Hash32;
    {
        let mut eng = engines[0].lock().await;
        assert_eq!(eng.state.step, Step::Propose);
        // height=1 round=0 proposer idx=(1+0)%5=1 => validator #2 (seed [2;32])
        let mut ob = outboxes[0].lock().await;
        assert!(producer.try_produce(&mut *eng, &ks[1], stores[0].as_ref(), &mut *ob, vec![]));
        block_id = eng.state.proposal.as_ref().unwrap().block_id.clone();
        assert!(stores[0].get(&block_id).is_some());
    }

    // Late joiners may miss consensus due to drops; replay bounded history a few times.
    for _ in 0..12 {
        for nid in 2..=5 {
            net1.replay_consensus_to(nid);
        }
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }

    // Deadline for eventual consistency
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(5);
    loop {
        let mut ok = 0;
        for s in &stores {
            if s.get(&block_id).is_some() { ok += 1; }
        }
        if ok == 5 { break; }
        if tokio::time::Instant::now() > deadline {
            panic!("not all nodes received the block by deadline; have {ok}/5");
        }
        tokio::time::sleep(std::time::Duration::from_millis(40)).await;
    }

    for t in tasks { t.abort(); }
}
