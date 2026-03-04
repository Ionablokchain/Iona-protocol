
use iona::consensus::{ConsensusMsg, SimpleBlockProducer, SimpleProducerCfg, Validator, ValidatorSet, BlockStore, Outbox, Engine};
use iona::crypto::ed25519::{Ed25519Keypair, Ed25519Verifier};
use iona::crypto::Signer;
use iona::types::{Hash32, Height};
use iona::slashing::StakeLedger;
use iona::consensus::DoubleSignGuard;
use iona::execution::KvState;

use std::collections::HashMap;

#[derive(Default)]
struct MemStore {
    blocks: std::sync::Mutex<HashMap<Hash32, iona::types::Block>>,
}
impl BlockStore for MemStore {
    fn get(&self, id: &Hash32) -> Option<iona::types::Block> {
        self.blocks.lock().ok()?.get(id).cloned()
    }
    fn put(&self, block: iona::types::Block) {
        if let Ok(mut m) = self.blocks.lock() {
            m.insert(block.id(), block);
        }
    }
}
#[derive(Default)]
struct TestOutbox {
    pub broadcasts: Vec<ConsensusMsg>,
}
impl Outbox for TestOutbox {
    fn broadcast(&mut self, msg: ConsensusMsg) { self.broadcasts.push(msg); }
    fn request_block(&mut self, _block_id: Hash32) {}
    fn on_commit(&mut self, _cert: &iona::consensus::CommitCertificate, _block: &iona::types::Block, _new_state: &KvState, _new_base_fee: u64, _receipts: &[iona::types::Receipt]) {}
}

fn make_engine(height: Height, vset: ValidatorSet) -> Engine<Ed25519Verifier> {
    let mut cfg = iona::consensus::Config::default();
    cfg.include_block_in_proposal = true;
    Engine::new(
        cfg,
        vset,
        height,
        Hash32([0u8; 32]),
        KvState::default(),
        StakeLedger::default(),
        None::<DoubleSignGuard>,
    )
}

#[test]
fn round_robin_producer_broadcasts_proposal() {
    // Deterministic keypairs
    let k1 = Ed25519Keypair::from_seed([1u8; 32]);
    let k2 = Ed25519Keypair::from_seed([2u8; 32]);
    let k3 = Ed25519Keypair::from_seed([3u8; 32]);

    let vset = ValidatorSet {
        vals: vec![
            Validator { pk: k1.public_key(), power: 1 },
            Validator { pk: k2.public_key(), power: 1 },
            Validator { pk: k3.public_key(), power: 1 },
        ],
    };

    let producer = SimpleBlockProducer::new(SimpleProducerCfg { max_txs: 0, include_block_in_proposal: true });
    let mut store = MemStore::default();
    let mut out = TestOutbox::default();

    // Height=1, round=0 => idx = (1+0)%3 = 1 => k2 is proposer
    let mut eng = make_engine(1, vset.clone());
    assert!(producer.try_produce(&mut eng, &k2, &store, &mut out, vec![]));
    assert!(out.broadcasts.iter().any(|m| matches!(m, ConsensusMsg::Proposal(_))), "expected Proposal broadcast");

    // Extract the proposal and ensure the block was persisted in the store.
    let prop = out.broadcasts.iter().find_map(|m| {
        if let ConsensusMsg::Proposal(p) = m { Some(p.clone()) } else { None }
    }).expect("proposal missing");
    let bid = prop.block_id.clone();
    assert!(store.get(&bid).is_some(), "expected block persisted");

    // Basic determinism: rebuilding an empty block at same height/round/prev should yield same id.
    let (rebuilt, _st2, _rcpts2) = iona::execution::build_block(
        eng.state.height,
        eng.state.round,
        eng.prev_block_id.clone(),
        k2.public_key().0.clone(),
        &hex::encode(&blake3::hash(&k2.public_key().0).as_bytes()[..20]),
        &eng.app_state,
        eng.base_fee_per_gas,
        vec![],
    );
    assert_eq!(rebuilt.id(), bid, "block id should be deterministic");

    // Height=2, round=0 => idx = 2%3 = 2 => k3 is proposer
    out.broadcasts.clear();
    eng.state.height = 2;
    eng.state.round = 0;
    eng.state.step = iona::consensus::Step::Propose;
    eng.state.proposal = None;
    eng.state.proposal_block = None;

    assert!(producer.try_produce(&mut eng, &k3, &store, &mut out, vec![]));
    assert!(out.broadcasts.iter().any(|m| matches!(m, ConsensusMsg::Proposal(_))));

    let prop2 = out.broadcasts.iter().find_map(|m| {
        if let ConsensusMsg::Proposal(p) = m { Some(p.clone()) } else { None }
    }).expect("proposal missing");
    assert!(store.get(&prop2.block_id).is_some(), "expected block persisted (height=2)");
}
