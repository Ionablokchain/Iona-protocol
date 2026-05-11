//! Test that the round‑robin block producer correctly selects the proposer,
//! broadcasts the proposal, and persists the block deterministically.

use iona::consensus::DoubleSignGuard;
use iona::consensus::{
    BlockStore, ConsensusMsg, Engine, Outbox, SimpleBlockProducer, SimpleProducerCfg, Validator,
    ValidatorSet,
};
use iona::crypto::ed25519::{Ed25519Keypair, Ed25519Verifier};
use iona::crypto::Signer;
use iona::execution::KvState;
use iona::slashing::StakeLedger;
use iona::types::{Block, Hash32, Height};

use std::collections::HashMap;
use std::sync::Mutex;

// -----------------------------------------------------------------------------
// Constants
// -----------------------------------------------------------------------------

/// Number of validators in the test network.
const NUM_VALIDATORS: usize = 3;

/// Power assigned to each validator.
const VALIDATOR_POWER: u64 = 1;

/// Initial block height.
const INITIAL_HEIGHT: Height = 1;

/// Next block height.
const NEXT_HEIGHT: Height = 2;

/// Round for the initial proposal.
const INITIAL_ROUND: u32 = 0;

/// Seeds for deterministic key generation.
const SEED_1: u8 = 1;
const SEED_2: u8 = 2;
const SEED_3: u8 = 3;

/// Expected proposer index for height = 1, round = 0 (1 + 0) % 3 = 1 → k2.
const INITIAL_PROPOSER_INDEX: usize = 1;

/// Expected proposer index for height = 2, round = 0 (2 + 0) % 3 = 2 → k3.
const NEXT_PROPOSER_INDEX: usize = 2;

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
struct TestOutbox {
    broadcasts: Vec<ConsensusMsg>,
}

impl Outbox for TestOutbox {
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

/// Create a consensus engine with default configuration.
fn make_engine(height: Height, vset: ValidatorSet) -> Engine<Ed25519Verifier> {
    let mut cfg = iona::consensus::Config::default();
    cfg.include_block_in_proposal = true;
    Engine::new(
        cfg,
        vset,
        height,
        Hash32::zero(),
        KvState::default(),
        StakeLedger::default(),
        None::<DoubleSignGuard>,
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
fn extract_proposal(outbox: &TestOutbox) -> iona::consensus::messages::Proposal {
    outbox
        .broadcasts
        .iter()
        .find_map(|msg| {
            if let ConsensusMsg::Proposal(prop) = msg {
                Some(prop.clone())
            } else {
                None
            }
        })
        .expect("No proposal broadcast found")
}

/// Rebuild an empty block for a given engine state and verify its ID matches the proposal.
fn assert_rebuilt_block_id_matches(
    engine: &Engine<Ed25519Verifier>,
    proposer_keypair: &Ed25519Keypair,
    proposer_address: &str,
    expected_id: &Hash32,
) {
    let (rebuilt, _state, _receipts) = iona::execution::build_block(
        engine.state.height,
        engine.state.round,
        engine.prev_block_id.clone(),
        proposer_keypair.public_key().0.clone(),
        proposer_address,
        &engine.app_state,
        engine.base_fee_per_gas,
        vec![],
    );
    assert_eq!(
        rebuilt.id(),
        *expected_id,
        "Rebuilt block ID does not match the stored proposal"
    );
}

// -----------------------------------------------------------------------------
// Test
// -----------------------------------------------------------------------------

#[test]
fn round_robin_producer_broadcasts_proposal() {
    // 1. Create deterministic keypairs for three validators.
    let key1 = keypair_from_seed(SEED_1);
    let key2 = keypair_from_seed(SEED_2);
    let key3 = keypair_from_seed(SEED_3);
    let keys = vec![key1, key2, key3];

    let validator_set = make_validator_set(&keys);
    let producer = SimpleBlockProducer::new(SimpleProducerCfg {
        max_txs: 0,
        include_block_in_proposal: true,
    });
    let store = MemStore::default();
    let mut outbox = TestOutbox::default();

    // 2. Height = 1, round = 0 → proposer index = (1 + 0) % 3 = 1 → key2.
    let mut engine = make_engine(INITIAL_HEIGHT, validator_set.clone());
    let proposer_key = &keys[INITIAL_PROPOSER_INDEX];
    let proposer_address = hex::encode(&blake3::hash(&proposer_key.public_key().0).as_bytes()[..20]);

    assert!(
        producer.try_produce(&mut engine, proposer_key, &store, &mut outbox, vec![]),
        "try_produce should succeed"
    );

    // Verify a proposal was broadcast.
    let proposal = extract_proposal(&outbox);
    let block_id = proposal.block_id.clone();
    assert!(
        store.get(&block_id).is_some(),
        "Proposed block must be persisted in the block store"
    );

    // 3. Determinism: rebuilding the same empty block must yield the same ID.
    assert_rebuilt_block_id_matches(
        &engine,
        proposer_key,
        &proposer_address,
        &block_id,
    );

    // 4. Height = 2, round = 0 → proposer index = (2 + 0) % 3 = 2 → key3.
    // Reset engine state.
    engine.state.height = NEXT_HEIGHT;
    engine.state.round = INITIAL_ROUND;
    engine.state.step = iona::consensus::Step::Propose;
    engine.state.proposal = None;
    engine.state.proposal_block = None;
    outbox.broadcasts.clear();

    let next_proposer_key = &keys[NEXT_PROPOSER_INDEX];
    let next_proposer_address = hex::encode(&blake3::hash(&next_proposer_key.public_key().0).as_bytes()[..20]);

    assert!(
        producer.try_produce(&mut engine, next_proposer_key, &store, &mut outbox, vec![]),
        "try_produce at height 2 should succeed"
    );

    let proposal2 = extract_proposal(&outbox);
    let block_id2 = proposal2.block_id.clone();
    assert!(
        store.get(&block_id2).is_some(),
        "Second block must be persisted"
    );

    assert_rebuilt_block_id_matches(
        &engine,
        next_proposer_key,
        &next_proposer_address,
        &block_id2,
    );
}
