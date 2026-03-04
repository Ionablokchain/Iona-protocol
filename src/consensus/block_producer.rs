//! Simple PoS block producer.
//!
//! This module is intentionally minimal: it does *one* thing — if the local node
//! is the designated proposer (round-robin) for the current height/round, it
//! builds a block from mempool transactions, signs a `Proposal`, persists the
//! block to the block store, and broadcasts the proposal over P2P.
//!
//! It does **not** create votes or handle quorum/finality. Those remain the
//! responsibility of the consensus engine (if enabled).

use crate::consensus::{proposal_sign_bytes, ConsensusMsg, Outbox, Proposal, Step};
use crate::crypto::Signer;
use crate::execution::build_block;
use crate::types::Tx;

/// Minimal producer configuration.
#[derive(Clone, Debug)]
pub struct SimpleProducerCfg {
    /// Maximum number of txs to include in a proposed block.
    pub max_txs: usize,
    /// Whether to embed the full block inside the proposal message.
    pub include_block_in_proposal: bool,
}

impl Default for SimpleProducerCfg {
    fn default() -> Self {
        Self {
            max_txs: 4096,
            include_block_in_proposal: true,
        }
    }
}

/// A simple round-robin PoS producer.
#[derive(Clone, Debug)]
pub struct SimpleBlockProducer {
    pub cfg: SimpleProducerCfg,
}

impl SimpleBlockProducer {
    pub fn new(cfg: SimpleProducerCfg) -> Self { Self { cfg } }

    /// Attempt to produce and broadcast a proposal for the engine's current height/round.
    ///
    /// Returns `true` if a proposal was produced.
    pub fn try_produce<V: crate::crypto::Verifier, S: Signer, B: crate::consensus::BlockStore, O: Outbox>(
        &self,
        engine: &mut crate::consensus::Engine<V>,
        signer: &S,
        store: &B,
        out: &mut O,
        txs: Vec<Tx>,
    ) -> bool {
        // Only propose in the Propose step.
        if engine.state.step != Step::Propose {
            return false;
        }
        // Don't double-propose.
        if engine.state.proposal.is_some() {
            return false;
        }
        // Only the designated proposer may produce.
        if !engine.is_proposer(&signer.public_key()) {
            return false;
        }

        // Deterministic proposer address (same as engine's internal helper).
        let proposer_addr = hex::encode(&blake3::hash(&signer.public_key().0).as_bytes()[..20]);

        // Build and persist the block.
        let (block, _next_state, _receipts) = build_block(
            engine.state.height,
            engine.state.round,
            engine.prev_block_id.clone(),
            signer.public_key().0.clone(),
            &proposer_addr,
            &engine.app_state,
            engine.base_fee_per_gas,
            txs.into_iter().take(self.cfg.max_txs).collect(),
        );

        let bid = block.id();
        store.put(block.clone());

        // Sign proposal.
        let sign_bytes = proposal_sign_bytes(engine.state.height, engine.state.round, &bid, engine.state.valid_round);
        let sig = signer.sign(&sign_bytes);

        let prop = Proposal {
            height: engine.state.height,
            round: engine.state.round,
            proposer: signer.public_key(),
            block_id: bid.clone(),
            block: if self.cfg.include_block_in_proposal { Some(block.clone()) } else { None },
            pol_round: engine.state.valid_round,
            signature: sig,
        };

        // Update local engine state so `Engine::tick` doesn't try to produce again.
        engine.state.proposal = Some(prop.clone());
        engine.state.proposal_block = Some(block);

        out.broadcast(ConsensusMsg::Proposal(prop));
        true
    }
}
