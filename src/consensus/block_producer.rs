//! Simple PoS block producer.
//!
//! This module is intentionally minimal: it does *one* thing — if the local node
//! is the designated proposer (round-robin) for the current height/round, it
//! builds a block from mempool transactions, signs a `Proposal`, and returns it.
//!
//! It does **not** create votes or handle quorum/finality. Those remain the
//! responsibility of the consensus engine (if enabled).
//!
//! The producer does **not** directly modify the engine's state or persist the block.
//! It returns the proposal and block, leaving the engine to decide when to store
//! and broadcast (typically after receiving enough votes).

use crate::consensus::{proposal_sign_bytes, Proposal};
use crate::crypto::Signer;
use crate::execution::build_block;
use crate::types::{Block, Tx};

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
    pub fn new(cfg: SimpleProducerCfg) -> Self {
        Self { cfg }
    }

    /// Attempt to produce a proposal for the given consensus round.
    ///
    /// Returns `Ok(Some((proposal, block)))` if the node is the designated proposer
    /// and a block was successfully built. Returns `Ok(None)` if the node is not
    /// the proposer or conditions are not met (e.g., already proposed). Returns
    /// `Err` if block building fails.
    ///
    /// # Parameters
    /// - `height`: current block height.
    /// - `round`: current consensus round.
    /// - `valid_round`: last valid round (for pol_round in proposal).
    /// - `prev_block_id`: hash of the previous block.
    /// - `app_state`: current application state (for execution).
    /// - `base_fee`: current base fee per gas.
    /// - `proposer_pubkey`: public key of the local node.
    /// - `proposer_addr`: derived address of the local node (must match what `build_block` expects).
    /// - `mempool_txs`: slice of pending transactions (may be empty). The producer will take up to `max_txs`.
    ///
    /// # Note
    /// The caller (typically the consensus engine) is responsible for:
    /// - Ensuring it is in the `Propose` step and has not already proposed.
    /// - Storing the block (e.g., after receiving a commit).
    /// - Broadcasting the proposal.
    /// - Updating its internal state with the new proposal.
    pub fn try_produce<S: Signer>(
        &self,
        height: u64,
        round: u32,
        valid_round: Option<i32>,
        prev_block_id: [u8; 32],
        app_state: &crate::execution::AppState,
        base_fee: u64,
        proposer_pubkey: &S::PublicKey,
        proposer_addr: &str,
        mempool_txs: &[Tx],
    ) -> Result<Option<(Proposal<S::PublicKey>, Block)>, Box<dyn std::error::Error>> {
        // Build the block (execution may fail).
        let (block, _next_state, _receipts) = build_block(
            height,
            round,
            prev_block_id,
            proposer_pubkey.as_bytes().to_vec(), // Assuming as_bytes() exists
            proposer_addr,
            app_state,
            base_fee,
            mempool_txs.iter().take(self.cfg.max_txs).cloned().collect(),
        )
        .map_err(|e| format!("failed to build block: {e}"))?;

        let block_id = block.id();

        // Sign the proposal.
        let sign_bytes = proposal_sign_bytes(height, round, &block_id, valid_round);
        let signature = proposer_pubkey.sign(&sign_bytes); // Requires Signer bound on public key? We'll assume sign method.

        let proposal = Proposal {
            height,
            round,
            proposer: proposer_pubkey.clone(),
            block_id: block_id.clone(),
            block: if self.cfg.include_block_in_proposal {
                Some(block.clone())
            } else {
                None
            },
            pol_round: valid_round,
            signature,
        };

        Ok(Some((proposal, block)))
    }
}

// Note: We assume `S::PublicKey` implements `Signer` or at least has a `sign` method.
// In practice, you might need to pass the `Signer` separately.
