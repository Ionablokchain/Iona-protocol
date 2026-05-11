//! Test that a proposal produced by the round‑robin producer is correctly
//! delivered to an observer via the consensus message wire.

use iona::consensus::{
    BlockStore, Config, ConsensusMsg, Engine, Outbox, SimpleBlockProducer, SimpleProducerCfg, Step,
    Validator, ValidatorSet,
};
use iona::crypto::ed25519::{Ed25519Keypair, Ed25519Verifier};
use iona::crypto::Signer;
use iona::execution::KvState;
use iona::slashing::StakeLedger;
use iona::types::{Block, Hash32};

use std::collections::HashMap;
use std::sync::Mutex;

// -----------------------------------------------------------------------------
// Constants
// -----------------------------------------------------------------------------

/// Number of validators in the test.
const NUM_VALIDATORS: usize = 2;

/// Power assigned to each validator.
const VALIDATOR_POWER: u64 = 1;

/// Initial block height.
const INITIAL_HEIGHT: u64 = 1;

/// Round for the initial proposal.
const INITIAL_ROUND: u32 = 0;

/// Seeds for deterministic key generation.
const SEED_VALIDATOR_1: u8 = 1;
const SEED_VALIDATOR_2: u8 = 2;

/// Expected proposer index for height = 1, round = 0: (1 + 0) % 2 = 1 → second validator.
const EXPECTED_PROPOSER_INDEX: usize = 1;

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

/// Simple outbox that records broadcast messages.
#[derive(Default)]
struct WireOutbox {
    broadcasts: Vec<ConsensusMsg>,
}

impl Outbox for WireOutbox {
    fn broadcast(&mut self, msg: ConsensusMsg) {
        self.broadcasts.push(msg);
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

/// Create a consensus engine with the given height and validator set.
fn make_engine(height: u64, vset: ValidatorSet) -> Engine<Ed25519Verifier> {
    let mut cfg = Config::default();
    cfg.include_block_in_proposal = true;
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

/// Generate a keypair from a single‑byte seed (padded to 32 bytes).
fn keypair_from_seed(seed: u8) -> Ed25519Keypair {
    Ed25519Keypair::from_seed([seed; 32])
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

/// Extract the first `Proposal` message from an outbox, or panic.
fn extract_proposal(outbox: &WireOutbox) -> ConsensusMsg {
    outbox
        .broadcasts
        .iter()
        .find(|msg| matches!(msg, ConsensusMsg::Proposal(_)))
        .expect("No proposal broadcast found")
        .clone()
}

// -----------------------------------------------------------------------------
// Test
// -----------------------------------------------------------------------------

#[test]
fn producer_to_observer_proposal_delivery() {
    // 1. Create deterministic keypairs for two validators.
    let key1 = keypair_from_seed(SEED_VALIDATOR_1);
    let key2 = keypair_from_seed(SEED_VALIDATOR_2);
    let keys = vec![key1, key2];

    let validator_set = make_validator_set(&keys);
    let proposer_key = &keys[EXPECTED_PROPOSER_INDEX];

    // 2. Create producer and observer engines.
    let producer_engine = make_engine(INITIAL_HEIGHT, validator_set.clone());
    let observer_engine = make_engine(INITIAL_HEIGHT, validator_set.clone());

    let store_producer = MemStore::default();
    let store_observer = MemStore::default();
    let mut outbox_producer = WireOutbox::default();
    let mut outbox_observer = WireOutbox::default();

    // 3. Producer engine should be in Propose step.
    let mut eng_producer = producer_engine;
    assert_eq!(eng_producer.state.step, Step::Propose);

    // 4. Produce a proposal.
    let producer = SimpleBlockProducer::new(SimpleProducerCfg {
        max_txs: 0,
        include_block_in_proposal: true,
    });
    assert!(
        producer.try_produce(&mut eng_producer, proposer_key, &store_producer, &mut outbox_producer, vec![]),
        "Producer failed to produce a proposal"
    );

    // 5. Deliver the proposal message to the observer.
    let proposal_msg = extract_proposal(&outbox_producer);
    let mut eng_observer = observer_engine;
    eng_observer
        .on_message(&keys[0], &store_observer, &mut outbox_observer, proposal_msg)
        .expect("Observer failed to process the proposal");

    // 6. Verify that the observer has stored the proposal in its state.
    assert!(
        eng_observer.state.proposal.is_some(),
        "Observer did not store the proposal"
    );
}
