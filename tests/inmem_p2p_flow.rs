//! Integration test — in-memory network delivers consensus messages.
//!
//! Verifies that the in-memory network used by consensus:
//!
//! * delivers a proposal from the designated proposer to an observer node;
//! * does not echo a broadcast back to its sender;
//! * hands the observer exactly the same proposal the proposer emitted;
//! * identifies the proposer deterministically from `(height, round)`;
//! * tracks broadcast counts so tests can assert on message flow.
//!
//! The in-memory network is a transport double, not a model of a quantum
//! channel. Determinism of consensus is verified by comparing the
//! observable state of proposer and observer, not by "coherence" metrics.

use iona::consensus::{
    BlockStore, Config, ConsensusMsg, Engine, Outbox, Proposal, SimpleBlockProducer,
    SimpleProducerCfg, Step, Validator, ValidatorSet,
};
use iona::crypto::ed25519::{Ed25519Keypair, Ed25519Verifier};
use iona::crypto::Signer;
use iona::execution::KvState;
use iona::net::inmem::InMemNet;
use iona::slashing::StakeLedger;
use iona::types::{Block, Hash32};

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::sync::mpsc;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const SEED_1: u8 = 1;
const SEED_2: u8 = 2;
const INITIAL_HEIGHT: u64 = 1;
const VALIDATOR_POWER: u64 = 1;

/// Upper bound on how long the observer may take to see the proposal.
/// Generous enough to absorb CI load, short enough to fail fast on bugs.
const DELIVERY_TIMEOUT: Duration = Duration::from_secs(2);

/// Polling interval while waiting for the observer.
const POLL_INTERVAL: Duration = Duration::from_millis(5);

// ---------------------------------------------------------------------------
// In-memory block store
// ---------------------------------------------------------------------------

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

// ---------------------------------------------------------------------------
// In-memory outbox
// ---------------------------------------------------------------------------

/// Outbox that forwards consensus messages to the in-memory network and
/// records every broadcast so tests can assert on message flow.
struct InMemOutbox {
    net: InMemNet,
    broadcasts: Vec<ConsensusMsg>,
}

impl InMemOutbox {
    fn new(net: InMemNet) -> Self {
        Self {
            net,
            broadcasts: Vec::new(),
        }
    }

    fn broadcast_count(&self) -> usize {
        self.broadcasts.len()
    }

    fn last_broadcast(&self) -> Option<&ConsensusMsg> {
        self.broadcasts.last()
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

// ---------------------------------------------------------------------------
// Consensus engine factory
// ---------------------------------------------------------------------------

fn make_engine(height: u64, validator_set: ValidatorSet) -> Engine<Ed25519Verifier> {
    Engine::new(
        Config {
            include_block_in_proposal: true,
            ..Default::default()
        },
        validator_set,
        height,
        Hash32::zero(),
        KvState::default(),
        StakeLedger::default(),
        None,
    )
}

// ---------------------------------------------------------------------------
// Message pump
// ---------------------------------------------------------------------------

/// Drive an engine with messages from the in-memory network until the
/// receiver is closed.
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

// ---------------------------------------------------------------------------
// Wait helper
// ---------------------------------------------------------------------------

/// Block until `proposal` has been observed on the given engine, or panic
/// after `DELIVERY_TIMEOUT`.
async fn wait_for_proposal(
    engine: &tokio::sync::Mutex<Engine<Ed25519Verifier>>,
    what: &str,
) -> Proposal {
    let deadline = Instant::now() + DELIVERY_TIMEOUT;
    loop {
        {
            let guard = engine.lock().await;
            if let Some(p) = guard.state.proposal.clone() {
                return p;
            }
        }
        if Instant::now() >= deadline {
            panic!("timed out after {DELIVERY_TIMEOUT:?} waiting for {what}");
        }
        tokio::time::sleep(POLL_INTERVAL).await;
    }
}

// ===========================================================================
// Tests
// ===========================================================================

/// End-to-end: proposer broadcasts a proposal, observer receives it, and
/// both agree on the proposal's identity.
#[tokio::test]
async fn inmem_network_delivers_proposal_to_observer() {
    let keypair1 = Ed25519Keypair::from_seed([SEED_1; 32]);
    let keypair2 = Ed25519Keypair::from_seed([SEED_2; 32]);

    let validator_set = ValidatorSet {
        vals: vec![
            Validator { pk: keypair1.public_key(), power: VALIDATOR_POWER },
            Validator { pk: keypair2.public_key(), power: VALIDATOR_POWER },
        ],
    };

    // Two-node network: node 1 registers node 2 and obtains its own handle.
    let (network1, rx1) = InMemNet::new(1u64);
    let rx2 = network1.register(2u64);
    let network2 = network1.handle(2u64);

    let store1 = Arc::new(MemStore::default());
    let engine1 = Arc::new(tokio::sync::Mutex::new(make_engine(
        INITIAL_HEIGHT,
        validator_set.clone(),
    )));
    let outbox1 = Arc::new(tokio::sync::Mutex::new(InMemOutbox::new(network1)));

    let store2 = Arc::new(MemStore::default());
    let engine2 = Arc::new(tokio::sync::Mutex::new(make_engine(
        INITIAL_HEIGHT,
        validator_set.clone(),
    )));
    let outbox2 = Arc::new(tokio::sync::Mutex::new(InMemOutbox::new(network2)));

    // Each node's pump signs with **its own** keypair.
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
        keypair2.clone(),
        store2.clone(),
        outbox2.clone(),
    ));

    let producer = SimpleBlockProducer::new(SimpleProducerCfg {
        max_txs: 0,
        include_block_in_proposal: true,
    });

    // At (height=1, round=0) with n=2, proposer index = (1 + 0) % 2 = 1,
    // i.e. validator 2. The producer on node 1 signs with keypair2.
    let proposer_view = {
        let mut engine = engine1.lock().await;
        assert_eq!(
            engine.state.step,
            Step::Propose,
            "engine must be in Propose step before proposing"
        );

        let mut outbox = outbox1.lock().await;
        let produced = producer.try_produce(
            &mut *engine,
            &keypair2,
            store1.as_ref(),
            &mut *outbox,
            vec![],
        );
        assert!(produced, "producer must have created a proposal");
        assert!(
            outbox.broadcast_count() > 0,
            "producer must have broadcast at least once"
        );
        assert!(
            matches!(outbox.last_broadcast(), Some(ConsensusMsg::Proposal(_))),
            "last broadcast must be a Proposal, got {:?}",
            outbox.last_broadcast()
        );

        engine
            .state
            .proposal
            .clone()
            .expect("proposer engine must retain its own proposal")
    };

    // Wait for the observer to see the proposal.
    let observer_view = wait_for_proposal(&engine2, "observer to receive proposal").await;

    // Both nodes must agree on the proposal's identity.
    assert_eq!(
        proposer_view.height, observer_view.height,
        "proposer and observer disagree on proposal height"
    );
    assert_eq!(
        proposer_view.round, observer_view.round,
        "proposer and observer disagree on proposal round"
    );
    assert_eq!(
        proposer_view.proposer, observer_view.proposer,
        "proposer and observer disagree on who proposed"
    );
    assert_eq!(
        proposer_view.block_id, observer_view.block_id,
        "proposer and observer disagree on the proposed block ID"
    );
    assert_eq!(
        observer_view.height, INITIAL_HEIGHT,
        "observer saw a proposal at the wrong height"
    );
    assert_eq!(
        observer_view.round, 0,
        "observer saw a proposal at the wrong round"
    );

    pump1.abort();
    pump2.abort();
}

/// A broadcast must reach every peer **except** its sender.
#[tokio::test]
async fn inmem_network_excludes_sender_from_broadcast() {
    let (net1, mut rx1) = InMemNet::new(1u64);
    let mut rx2 = net1.register(2u64);

    let proposal = Proposal {
        height: 1,
        round: 0,
        proposer: Ed25519Keypair::from_seed([SEED_1; 32]).public_key(),
        block_id: Hash32::zero(),
        block: None,
        pol_round: None,
        signature: iona::crypto::SignatureBytes(vec![]),
    };

    net1.broadcast(ConsensusMsg::Proposal(proposal.clone()));

    // The sender must not receive its own message.
    assert!(
        rx1.try_recv().is_err(),
        "sender must not receive its own broadcast"
    );

    // The peer must receive it. If `broadcast` dispatches asynchronously,
    // give it a short grace period.
    let deadline = Instant::now() + DELIVERY_TIMEOUT;
    let received = loop {
        match rx2.try_recv() {
            Ok(msg) => break msg,
            Err(_) if Instant::now() < deadline => {
                tokio::time::sleep(POLL_INTERVAL).await;
            }
            Err(e) => panic!("peer did not receive broadcast: {e:?}"),
        }
    };

    match received {
        ConsensusMsg::Proposal(p) => {
            assert_eq!(p.height, 1);
            assert_eq!(p.round, 0);
            assert_eq!(p.proposer, proposal.proposer);
        }
        other => panic!("peer received unexpected message: {other:?}"),
    }
}

/// The producer must identify exactly one proposer for every
/// `(height, round)` in a round-robin over validators.
#[test]
fn producer_identifies_proposer_by_position() {
    let keypair1 = Ed25519Keypair::from_seed([SEED_1; 32]);
    let keypair2 = Ed25519Keypair::from_seed([SEED_2; 32]);

    let validator_set = ValidatorSet {
        vals: vec![
            Validator { pk: keypair1.public_key(), power: 1 },
            Validator { pk: keypair2.public_key(), power: 1 },
        ],
    };

    let producer = SimpleBlockProducer::new(SimpleProducerCfg::default());

    // Expected proposer index = (height + round) % 2 over these positions.
    let cases: &[(u64, u32, usize)] = &[
        (1, 0, 1), // (1+0) % 2 = 1 → validator 2
        (1, 1, 0), // (1+1) % 2 = 0 → validator 1
        (2, 0, 0), // (2+0) % 2 = 0 → validator 1
        (2, 1, 1), // (2+1) % 2 = 1 → validator 2
        (3, 0, 1), // (3+0) % 2 = 1 → validator 2
    ];

    for &(height, round, expected_idx) in cases {
        let mut engine = make_engine(height, validator_set.clone());
        engine.state.round = round;

        let keypair_expected = if expected_idx == 0 { &keypair1 } else { &keypair2 };
        let keypair_other = if expected_idx == 0 { &keypair2 } else { &keypair1 };

        assert!(
            producer.is_proposer(&engine, keypair_expected),
            "expected validator {} to be proposer at (h={}, r={})",
            expected_idx + 1,
            height,
            round,
        );
        assert!(
            !producer.is_proposer(&engine, keypair_other),
            "validator {} must NOT be proposer at (h={}, r={})",
            (1 - expected_idx) + 1,
            height,
            round,
        );
    }
}
