//! Integration test — In‑memory network delivers consensus messages.
//!
//! # Quantum Network Model
//!
//! The in‑memory network is modelled as a **quantum channel** Φ_net that
//! transmits consensus states between validators.  Each message delivery
//! is a **Kraus operator** K_deliver that projects the state onto the
//! recipient's Hilbert space with high fidelity.
//!
//! # Test Coverage
//!
//! - Validator setup and round‑robin proposer selection
//! - Proposal broadcast via InMemNet
//! - Asynchronous message delivery verification
//! - Quantum coherence tracking after transmission

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
// Quantum Constants
// -----------------------------------------------------------------------------

/// Reduced Planck constant (natural units).
const HBAR: f64 = 1.0;

/// Default quantum coherence for a fresh network state.
const DEFAULT_NETWORK_COHERENCE: f64 = 1.0;

/// Decoherence rate per message transmission.
const TRANSMISSION_DECOHERENCE_RATE: f64 = 0.0001;

/// Minimum coherence threshold for a healthy network.
const MIN_NETWORK_COHERENCE: f64 = 0.99;

/// Kraus rank for network quantum channels.
const NETWORK_KRAUS_RANK: usize = 4;

// -----------------------------------------------------------------------------
// Classical Constants
// -----------------------------------------------------------------------------

const DEFAULT_SEED_1: u8 = 1;
const DEFAULT_SEED_2: u8 = 2;
const INITIAL_HEIGHT: u64 = 1;
const VALIDATOR_POWER: u64 = 1;
const NETWORK_DELAY_MS: u64 = 20;

// -----------------------------------------------------------------------------
// Quantum Network Test State
// -----------------------------------------------------------------------------

/// Quantum state tracker for network integration tests.
///
/// Tracks the density matrix properties during message transmission
/// and verifies that the network maintains quantum coherence.
#[derive(Debug, Clone)]
struct QuantumNetworkTestState {
    /// Purity γ = Tr(ρ²) of the network state.
    purity: f64,
    /// Von Neumann entropy S = -Tr(ρ ln ρ).
    entropy: f64,
    /// Coherence of the message transmission.
    transmission_coherence: f64,
    /// Number of messages transmitted.
    message_count: u64,
    /// Whether the network is healthy.
    is_healthy: bool,
}

impl QuantumNetworkTestState {
    fn new() -> Self {
        Self {
            purity: DEFAULT_NETWORK_COHERENCE,
            entropy: 0.0,
            transmission_coherence: DEFAULT_NETWORK_COHERENCE,
            message_count: 0,
            is_healthy: true,
        }
    }

    /// Apply decoherence from a message transmission.
    fn apply_transmission_decoherence(&mut self) {
        self.message_count = self.message_count.wrapping_add(1);
        let decay = (-TRANSMISSION_DECOHERENCE_RATE).exp();
        self.transmission_coherence = (self.transmission_coherence * decay).clamp(0.0, 1.0);
        self.recompute();
    }

    /// Apply the Kraus channel for network operations.
    fn apply_network_channel(&mut self) {
        let kraus_factor = (1.0 / NETWORK_KRAUS_RANK as f64).sqrt();
        self.transmission_coherence = (self.transmission_coherence * kraus_factor).clamp(0.0, 1.0);
        self.recompute();
    }

    fn recompute(&mut self) {
        self.purity = self.transmission_coherence;
        self.entropy = if self.purity >= 1.0 {
            0.0
        } else {
            -self.purity * self.purity.ln().max(0.0)
        };
        self.is_healthy = self.purity >= MIN_NETWORK_COHERENCE;
    }
}

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

/// Outbox that broadcasts over the in‑memory network and records
/// broadcasts for inspection.
struct InMemOutbox {
    net: InMemNet,
    pub broadcasts: Vec<ConsensusMsg>,
    /// Quantum state tracker for transmission fidelity.
    quantum: QuantumNetworkTestState,
}

impl InMemOutbox {
    fn new(net: InMemNet) -> Self {
        Self {
            net,
            broadcasts: Vec::new(),
            quantum: QuantumNetworkTestState::new(),
        }
    }

    /// Get the quantum purity after transmissions.
    fn purity(&self) -> f64 {
        self.quantum.purity
    }

    /// Check if the network state is healthy.
    fn is_healthy(&self) -> bool {
        self.quantum.is_healthy
    }
}

impl Outbox for InMemOutbox {
    fn broadcast(&mut self, msg: ConsensusMsg) {
        self.broadcasts.push(msg.clone());
        self.net.broadcast(msg);
        self.quantum.apply_transmission_decoherence();
        self.quantum.apply_network_channel();
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

// ═══════════════════════════════════════════════════════════════════════════════
// Integration Tests
// ═══════════════════════════════════════════════════════════════════════════════

/// Verify that an in‑memory network delivers a proposal from the proposer
/// to an observer node.
#[tokio::test]
async fn inmem_network_delivers_proposal_to_observer() {
    let mut qstate = QuantumNetworkTestState::new();

    // ── Validator setup ──────────────────────────────────────────────
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

    // ── Network setup ────────────────────────────────────────────────
    let (network1, rx1) = InMemNet::new(1u64);
    let rx2 = network1.register(2u64);
    let network2 = network1.handle(2u64);

    qstate.apply_network_channel();

    // ── Node 1 (proposer) components ─────────────────────────────────
    let store1 = Arc::new(MemStore::default());
    let engine1 = Arc::new(tokio::sync::Mutex::new(make_engine(
        INITIAL_HEIGHT,
        validator_set.clone(),
    )));
    let outbox1 = Arc::new(tokio::sync::Mutex::new(InMemOutbox::new(network1)));

    // ── Node 2 (observer) components ─────────────────────────────────
    let store2 = Arc::new(MemStore::default());
    let engine2 = Arc::new(tokio::sync::Mutex::new(make_engine(
        INITIAL_HEIGHT,
        validator_set.clone(),
    )));
    let outbox2 = Arc::new(tokio::sync::Mutex::new(InMemOutbox::new(network2)));

    // ── Start message pumps ──────────────────────────────────────────
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

    // ── Propose a block ──────────────────────────────────────────────
    let producer = SimpleBlockProducer::new(SimpleProducerCfg {
        max_txs: 0,
        include_block_in_proposal: true,
    });

    {
        let mut engine = engine1.lock().await;
        // At height 1, round 0: proposer index = (1 + 0) % 2 = 1 → validator 2
        assert_eq!(
            engine.state.step,
            Step::Propose,
            "engine must be in Propose step"
        );
        let mut outbox = outbox1.lock().await;
        let produced = producer.try_produce(
            &mut *engine,
            &keypair2, // Producer should be validator 2
            store1.as_ref(),
            &mut *outbox,
            vec![],
        );
        assert!(
            produced,
            "producer should have created a proposal"
        );

        // Verify that the proposal was broadcast
        assert!(
            !outbox.broadcasts.is_empty(),
            "outbox should contain at least one broadcast"
        );
        assert!(
            matches!(outbox.broadcasts.last(), Some(ConsensusMsg::Proposal(_))),
            "last broadcast should be a Proposal"
        );

        // Verify quantum state is still healthy after transmission
        assert!(
            outbox.is_healthy(),
            "network should be healthy after one broadcast"
        );
        assert!(
            outbox.purity() < DEFAULT_NETWORK_COHERENCE,
            "transmission should cause minor decoherence"
        );
    }

    // ── Wait for message delivery ────────────────────────────────────
    tokio::time::sleep(std::time::Duration::from_millis(NETWORK_DELAY_MS)).await;

    // ── Verify observer received the proposal ────────────────────────
    {
        let engine = engine2.lock().await;
        assert!(
            engine.state.proposal.is_some(),
            "observer must have received the proposal"
        );

        let proposal = engine.state.proposal.as_ref().unwrap();
        assert_eq!(
            proposal.height, INITIAL_HEIGHT,
            "proposal height must match"
        );
        assert_eq!(proposal.round, 0, "proposal round must be 0");
    }

    // ── Verify quantum state after full transmission ─────────────────
    {
        let outbox = outbox1.lock().await;
        assert!(
            outbox.message_count() > 0,
            "should have recorded message transmissions"
        );
    }

    // ── Clean up ─────────────────────────────────────────────────────
    pump1.abort();
    pump2.abort();
}

/// Verify that the in‑memory network correctly excludes the sender
/// from receiving its own broadcasts.
#[tokio::test]
async fn inmem_network_excludes_sender_from_broadcast() {
    let (net1, mut rx1) = InMemNet::new(1u64);
    let _rx2 = net1.register(2u64);

    // Broadcast from node 1
    net1.broadcast(ConsensusMsg::Proposal(iona::consensus::Proposal {
        height: 1,
        round: 0,
        proposer: Ed25519Keypair::from_seed([1; 32]).public_key(),
        block_id: Hash32::zero(),
        block: None,
        pol_round: None,
        signature: iona::crypto::SignatureBytes(vec![]),
    }));

    // Node 1 should NOT receive its own broadcast
    assert!(
        rx1.try_recv().is_err(),
        "sender must not receive its own broadcast"
    );
}

/// Verify that the producer correctly identifies whether it is the
/// designated proposer.
#[test]
fn producer_is_proposer_identification() {
    let keypair1 = Ed25519Keypair::from_seed([1; 32]);
    let keypair2 = Ed25519Keypair::from_seed([2; 32]);

    let validator_set = ValidatorSet {
        vals: vec![
            Validator {
                pk: keypair1.public_key(),
                power: 1,
            },
            Validator {
                pk: keypair2.public_key(),
                power: 1,
            },
        ],
    };

    let engine = make_engine(1, validator_set);
    let producer = SimpleBlockProducer::new(SimpleProducerCfg::default());

    // At height 1, round 0: proposer index = (1 + 0) % 2 = 1 → validator 2
    assert!(
        !producer.is_proposer(&engine, &keypair1),
        "validator 1 should NOT be proposer at height 1, round 0"
    );
    assert!(
        producer.is_proposer(&engine, &keypair2),
        "validator 2 should BE proposer at height 1, round 0"
    );
}
