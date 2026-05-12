//! Simple PoS block producer.
//!
//! This module is intentionally minimal: it does *one* thing — if the local node
//! is the designated proposer (round‑robin) for the current height/round, it
//! builds a block from mempool transactions, signs a `Proposal`, persists the
//! block to the block store, and broadcasts the proposal over P2P.
//!
//! It does **not** create votes or handle quorum/finality. Those remain the
//! responsibility of the consensus engine (if enabled).
//!
//! # Example
//!
//! ```rust,ignore
//! use iona::consensus::block_producer::{SimpleBlockProducer, SimpleProducerCfg};
//!
//! let cfg = SimpleProducerCfg::default();
//! let producer = SimpleBlockProducer::new(cfg);
//! let txs = mempool.drain_best(cfg.max_txs);
//! if producer.try_produce(&mut engine, &signer, &store, &mut outbox, txs) {
//!     println!("Proposal broadcast");
//! }
//! ```

use crate::consensus::{proposal_sign_bytes, ConsensusMsg, Outbox, Proposal, Step};
use crate::crypto::Signer;
use crate::execution::build_block;
use crate::types::Tx;
use tracing::{debug, info, warn};

// -----------------------------------------------------------------------------
// Constants
// -----------------------------------------------------------------------------

/// Default maximum number of transactions to include in a proposed block.
const DEFAULT_MAX_TXS: usize = 4096;

/// Default setting: embed full block inside the proposal message.
const DEFAULT_INCLUDE_BLOCK: bool = true;

// -----------------------------------------------------------------------------
// Configuration
// -----------------------------------------------------------------------------

/// Minimal producer configuration.
#[derive(Clone, Debug)]
pub struct SimpleProducerCfg {
    /// Maximum number of transactions to include in a proposed block.
    pub max_txs: usize,
    /// Whether to embed the full block inside the proposal message.
    /// If `false`, peers must request the block separately.
    pub include_block_in_proposal: bool,
}

impl Default for SimpleProducerCfg {
    fn default() -> Self {
        Self {
            max_txs: DEFAULT_MAX_TXS,
            include_block_in_proposal: DEFAULT_INCLUDE_BLOCK,
        }
    }
}

// -----------------------------------------------------------------------------
// Producer
// -----------------------------------------------------------------------------

/// A simple round‑robin PoS producer.
#[derive(Clone, Debug)]
pub struct SimpleBlockProducer {
    pub cfg: SimpleProducerCfg,
}

impl SimpleBlockProducer {
    /// Create a new producer with the given configuration.
    pub fn new(cfg: SimpleProducerCfg) -> Self {
        Self { cfg }
    }

    /// Check if the local node is the proposer for the current engine state.
    pub fn is_proposer<V: crate::crypto::Verifier>(
        &self,
        engine: &crate::consensus::Engine<V>,
        signer: &dyn Signer,
    ) -> bool {
        engine.is_proposer(&signer.public_key())
    }

    /// Derive the proposer address (20‑byte hex) from a public key.
    /// This matches the address used in `build_block`.
    pub fn proposer_address(signer: &dyn Signer) -> String {
        hex::encode(&blake3::hash(&signer.public_key().0).as_bytes()[..20])
    }

    /// Attempt to produce and broadcast a proposal for the engine's current height/round.
    ///
    /// Returns `true` if a proposal was produced and broadcast.
    ///
    /// # Conditions
    /// - Engine must be in `Propose` step.
    /// - No proposal already exists for this round.
    /// - Local node must be the designated proposer.
    pub fn try_produce<
        V: crate::crypto::Verifier,
        S: Signer,
        B: crate::consensus::BlockStore,
        O: Outbox,
    >(
        &self,
        engine: &mut crate::consensus::Engine<V>,
        signer: &S,
        store: &B,
        out: &mut O,
        txs: Vec<Tx>,
    ) -> bool {
        // Only propose in the Propose step.
        if engine.state.step != Step::Propose {
            debug!(step = ?engine.state.step, "not in propose step, skipping proposal");
            return false;
        }

        // Don't double‑propose.
        if engine.state.proposal.is_some() {
            debug!("proposal already exists for this round");
            return false;
        }

        // Only the designated proposer may produce.
        if !engine.is_proposer(&signer.public_key()) {
            debug!("not the designated proposer");
            return false;
        }

        info!(
            height = engine.state.height,
            round = engine.state.round,
            "producing proposal"
        );

        let proposer_addr = Self::proposer_address(signer);

        // Build the block.
        let txs_to_include: Vec<Tx> = txs.into_iter().take(self.cfg.max_txs).collect();
        let (block, _next_state, _receipts) = build_block(
            engine.state.height,
            engine.state.round,
            engine.prev_block_id.clone(),
            signer.public_key().0.clone(),
            &proposer_addr,
            &engine.app_state,
            engine.base_fee_per_gas,
            txs_to_include,
        );

        let block_id = block.id();
        debug!(block_id = %hex::encode(&block_id.0[..8]), tx_count = block.txs.len(), "block built");

        // Store the block.
        store.put(block.clone());

        // Sign the proposal.
        let sign_bytes = proposal_sign_bytes(
            engine.state.height,
            engine.state.round,
            &block_id,
            engine.state.valid_round,
        );
        let signature = signer.sign(&sign_bytes);

        let proposal = Proposal {
            height: engine.state.height,
            round: engine.state.round,
            proposer: signer.public_key(),
            block_id: block_id.clone(),
            block: if self.cfg.include_block_in_proposal {
                Some(block.clone())
            } else {
                None
            },
            pol_round: engine.state.valid_round,
            signature,
        };

        // Update local engine state so `Engine::tick` doesn't try to produce again.
        engine.state.proposal = Some(proposal.clone());
        engine.state.proposal_block = Some(block);

        out.broadcast(ConsensusMsg::Proposal(proposal));
        info!(
            height = engine.state.height,
            round = engine.state.round,
            block_id = %hex::encode(&block_id.0[..8]),
            "proposal broadcast"
        );

        true
    }
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::consensus::{engine::Config, validator_set::ValidatorSet, Engine};
    use crate::crypto::ed25519::{Ed25519Keypair, Ed25519Verifier};
    use crate::crypto::Signer;
    use crate::execution::KvState;
    use crate::slashing::StakeLedger;
    use crate::types::{Hash32, Height};

    /// Mock block store for testing.
    struct MockBlockStore {
        blocks: std::sync::Mutex<std::collections::HashMap<Hash32, crate::types::Block>>,
    }
    impl MockBlockStore {
        fn new() -> Self {
            Self {
                blocks: std::sync::Mutex::new(std::collections::HashMap::new()),
            }
        }
    }
    impl crate::consensus::BlockStore for MockBlockStore {
        fn get(&self, id: &Hash32) -> Option<crate::types::Block> {
            self.blocks.lock().unwrap().get(id).cloned()
        }
        fn put(&self, block: crate::types::Block) {
            self.blocks.lock().unwrap().insert(block.id(), block);
        }
    }

    /// Mock outbox that records broadcasts.
    struct MockOutbox {
        broadcasts: std::sync::Mutex<Vec<ConsensusMsg>>,
    }
    impl MockOutbox {
        fn new() -> Self {
            Self {
                broadcasts: std::sync::Mutex::new(Vec::new()),
            }
        }
        fn last_proposal(&self) -> Option<Proposal> {
            self.broadcasts
                .lock()
                .unwrap()
                .iter()
                .filter_map(|msg| match msg {
                    ConsensusMsg::Proposal(p) => Some(p.clone()),
                    _ => None,
                })
                .last()
        }
    }
    impl Outbox for MockOutbox {
        fn broadcast(&mut self, msg: ConsensusMsg) {
            self.broadcasts.lock().unwrap().push(msg);
        }
        fn request_block(&mut self, _block_id: Hash32) {}
        fn on_commit(
            &mut self,
            _cert: &crate::consensus::CommitCertificate,
            _block: &crate::types::Block,
            _new_state: &KvState,
            _new_base_fee: u64,
            _receipts: &[crate::types::Receipt],
        ) {
        }
    }

    fn make_engine(proposer_pk: &Ed25519Keypair) -> Engine<Ed25519Verifier> {
        let vset = ValidatorSet {
            vals: vec![crate::consensus::validator_set::Validator {
                pk: proposer_pk.public_key(),
                power: 1,
            }],
        };
        Engine::new(
            Config::default(),
            vset,
            1,
            Hash32::zero(),
            KvState::default(),
            StakeLedger::default(),
            None,
        )
    }

    #[test]
    fn test_producer_proposes_when_proposer() {
        let signer = Ed25519Keypair::from_seed([1u8; 32]);
        let mut engine = make_engine(&signer);
        let store = MockBlockStore::new();
        let mut outbox = MockOutbox::new();
        let producer = SimpleBlockProducer::new(SimpleProducerCfg::default());

        assert_eq!(engine.state.step, Step::Propose);
        assert!(engine.state.proposal.is_none());

        let result = producer.try_produce(&mut engine, &signer, &store, &mut outbox, vec![]);

        assert!(result);
        assert!(engine.state.proposal.is_some());
        let proposal = outbox.last_proposal().unwrap();
        assert_eq!(proposal.height, 1);
        assert_eq!(proposal.round, 0);
        assert_eq!(proposal.proposer, signer.public_key());
    }

    #[test]
    fn test_producer_does_not_propose_when_not_proposer() {
        let proposer = Ed25519Keypair::from_seed([1u8; 32]);
        let non_proposer = Ed25519Keypair::from_seed([2u8; 32]);
        let mut engine = make_engine(&proposer);
        let store = MockBlockStore::new();
        let mut outbox = MockOutbox::new();
        let producer = SimpleBlockProducer::new(SimpleProducerCfg::default());

        let result = producer.try_produce(&mut engine, &non_proposer, &store, &mut outbox, vec![]);
        assert!(!result);
        assert!(outbox.last_proposal().is_none());
    }

    #[test]
    fn test_producer_does_not_propose_twice() {
        let signer = Ed25519Keypair::from_seed([1u8; 32]);
        let mut engine = make_engine(&signer);
        let store = MockBlockStore::new();
        let mut outbox = MockOutbox::new();
        let producer = SimpleBlockProducer::new(SimpleProducerCfg::default());

        let first = producer.try_produce(&mut engine, &signer, &store, &mut outbox, vec![]);
        assert!(first);
        let second = producer.try_produce(&mut engine, &signer, &store, &mut outbox, vec![]);
        assert!(!second);
    }

    #[test]
    fn test_producer_respects_max_txs() {
        let signer = Ed25519Keypair::from_seed([1u8; 32]);
        let mut engine = make_engine(&signer);
        let store = MockBlockStore::new();
        let mut outbox = MockOutbox::new();
        let cfg = SimpleProducerCfg {
            max_txs: 2,
            include_block_in_proposal: true,
        };
        let producer = SimpleBlockProducer::new(cfg);

        let txs: Vec<Tx> = (0..5)
            .map(|i| Tx {
                pubkey: vec![],
                from: format!("sender{}", i),
                nonce: i,
                max_fee_per_gas: 0,
                max_priority_fee_per_gas: 0,
                gas_limit: 21_000,
                payload: "test".into(),
                signature: vec![],
                chain_id: 1,
            })
            .collect();

        let result = producer.try_produce(&mut engine, &signer, &store, &mut outbox, txs);
        assert!(result);

        let proposal = outbox.last_proposal().unwrap();
        let block = proposal.block.as_ref().unwrap();
        assert_eq!(block.txs.len(), 2);
    }

    #[test]
    fn test_proposer_address_derivation() {
        let signer = Ed25519Keypair::from_seed([42u8; 32]);
        let addr = SimpleBlockProducer::proposer_address(&signer);
        assert_eq!(addr.len(), 40); // 20 bytes in hex = 40 chars
        assert!(addr.chars().all(|c| c.is_ascii_hexdigit()));
    }
}
