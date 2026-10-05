//! Simple PoS block producer — production‑grade.
//!
//! This module implements a minimal round‑robin block producer. When the
//! local node is the designated proposer for the current height/round, it:
//! 1. Validates that all preconditions are met.
//! 2. Drains transactions from the mempool (up to `max_txs`).
//! 3. Builds a deterministic block using `build_block`.
//! 4. Persists the block to the block store.
//! 5. Signs and broadcasts a `Proposal` message over P2P.
//!
//! The producer does **not** handle voting, quorum, or finality — those
//! are the responsibility of the consensus engine.
//!
//! # Preconditions
//!
//! `try_produce` returns `Ok(false)` (soft skip) when any precondition fails:
//! wrong step, proposal already exists, or node is not the proposer. It never
//! mutates engine/store state in those cases.
//!
//! `try_produce_strict` returns a typed error for each failed precondition,
//! which is useful for callers that need explicit diagnostics or metrics.
//!
//! # Failure semantics
//!
//! If `store.put` fails, engine state is **not** mutated (the block build is
//! the last expensive step, and the write happens before any state change).
//! Receipt persistence failures are logged but do not fail the proposal.
//!
//! # Example
//!
//! ```rust,ignore
//! use iona::consensus::block_producer::{SimpleBlockProducer, ProducerConfig, ProducerError};
//!
//! let cfg = ProducerConfig::default();
//! let producer = SimpleBlockProducer::new(cfg)?;
//! match producer.try_produce(&mut engine, &signer, &store, &mut outbox, txs, &econ)? {
//!     Ok(true) => println!("Proposal broadcast"),
//!     Ok(false) => println!("Not our turn"),
//!     Err(e) => eprintln!("Production failed: {e}"),
//! }
//! ```

use crate::consensus::{proposal_sign_bytes, ConsensusMsg, Outbox, Proposal, Step};
use crate::crypto::Signer;
use crate::economics::params::EconomicsParams;
use crate::execution::build_block;
use crate::types::{Block, Tx};
use thiserror::Error;
use tracing::{debug, info, trace, warn};

// -----------------------------------------------------------------------------
// Constants
// -----------------------------------------------------------------------------

/// Default maximum number of transactions per block.
const DEFAULT_MAX_TXS: usize = 4096;

/// Default: embed full block inside the proposal message.
const DEFAULT_INCLUDE_BLOCK: bool = true;

/// Minimum allowed value for `max_txs`.
const MIN_MAX_TXS: usize = 1;

/// Maximum allowed value for `max_txs` (prevents memory exhaustion).
const MAX_ALLOWED_TXS: usize = 100_000;

/// Default max gas per block.
const DEFAULT_MAX_GAS_PER_BLOCK: u64 = 30_000_000;

// -----------------------------------------------------------------------------
// Error types
// -----------------------------------------------------------------------------

/// Errors that can occur during block production.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum ProducerError {
    #[error("invalid configuration: max_txs={max_txs}, must be {min}..={max}")]
    InvalidMaxTxs {
        max_txs: usize,
        min: usize,
        max: usize,
    },

    #[error("invalid configuration: max_gas_per_block must be > 0")]
    InvalidMaxGas,

    #[error("engine not in Propose step (current: {step:?})")]
    NotInProposeStep { step: Step },

    #[error("proposal already exists for round {round}")]
    ProposalAlreadyExists { round: u32 },

    #[error("node is not the designated proposer for height {height}, round {round}")]
    NotProposer { height: u64, round: u32 },

    #[error("block store error: {reason}")]
    BlockStoreError { reason: String },

    /// Reserved: returned by [`SimpleBlockProducer::try_produce_strict`] when
    /// `build_block` signals a recoverable build failure. Kept for forward
    /// compatibility with callers that pattern-match on the enum.
    #[error("block building failed: {reason}")]
    BlockBuildError { reason: String },

    /// Reserved: returned if the signer implementation ever gains a
    /// fallible `sign` API. Currently `Signer::sign` is infallible, so this
    /// variant is not produced by the built-in producer.
    #[error("signing failed: {reason}")]
    SigningError { reason: String },

    #[error("proposer address derivation failed: {reason}")]
    ProposerAddressError { reason: String },

    #[error("transaction list exceeds max_txs: {count} > {max}")]
    TransactionLimitExceeded { count: usize, max: usize },
}

/// Result type for producer operations.
pub type ProducerResult<T> = Result<T, ProducerError>;

// -----------------------------------------------------------------------------
// Configuration
// -----------------------------------------------------------------------------

/// Producer configuration with validation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProducerConfig {
    /// Maximum number of transactions to include in a proposed block.
    pub max_txs: usize,
    /// Whether to embed the full block inside the proposal message.
    /// If `false`, peers must request the block separately.
    pub include_block_in_proposal: bool,
    /// Maximum gas per block (enforced during block building).
    pub max_gas_per_block: u64,
    /// If `true`, `try_produce` returns typed precondition errors instead of
    /// the soft `Ok(false)` skip. Default: `false` (backward compatible).
    pub strict_preconditions: bool,
}

impl Default for ProducerConfig {
    fn default() -> Self {
        Self {
            max_txs: DEFAULT_MAX_TXS,
            include_block_in_proposal: DEFAULT_INCLUDE_BLOCK,
            max_gas_per_block: DEFAULT_MAX_GAS_PER_BLOCK,
            strict_preconditions: false,
        }
    }
}

impl ProducerConfig {
    /// Validate the configuration.
    pub fn validate(&self) -> ProducerResult<()> {
        if self.max_txs < MIN_MAX_TXS || self.max_txs > MAX_ALLOWED_TXS {
            return Err(ProducerError::InvalidMaxTxs {
                max_txs: self.max_txs,
                min: MIN_MAX_TXS,
                max: MAX_ALLOWED_TXS,
            });
        }
        if self.max_gas_per_block == 0 {
            return Err(ProducerError::InvalidMaxGas);
        }
        Ok(())
    }
}

// -----------------------------------------------------------------------------
// Producer
// -----------------------------------------------------------------------------

/// A simple round‑robin PoS block producer.
///
/// The producer is stateless — all state is held by the consensus engine,
/// block store, and mempool. This struct only holds validated configuration.
#[derive(Clone, Debug)]
pub struct SimpleBlockProducer {
    cfg: ProducerConfig,
}

impl SimpleBlockProducer {
    /// Create a new producer with the given configuration.
    ///
    /// Returns an error if the configuration is invalid.
    pub fn new(cfg: ProducerConfig) -> ProducerResult<Self> {
        cfg.validate()?;
        Ok(Self { cfg })
    }

    /// Read-only access to the validated configuration.
    pub fn config(&self) -> &ProducerConfig {
        &self.cfg
    }

    /// Derive the proposer address (20‑byte hex) from a signer's public key.
    /// This matches the address format used in `build_block`.
    pub fn proposer_address(signer: &dyn Signer) -> Result<String, ProducerError> {
        let pk_bytes = &signer.public_key().0;
        if pk_bytes.len() < 20 {
            return Err(ProducerError::ProposerAddressError {
                reason: format!("public key too short: {} bytes", pk_bytes.len()),
            });
        }
        let hash = blake3::hash(pk_bytes);
        Ok(hex::encode(&hash.as_bytes()[..20]))
    }

    /// Check if the local node is the proposer for the current engine state.
    pub fn is_proposer<V: crate::crypto::Verifier>(
        &self,
        engine: &crate::consensus::Engine<V>,
        signer: &dyn Signer,
    ) -> bool {
        engine.is_proposer(&signer.public_key())
    }

    /// Attempt to produce and broadcast a proposal.
    ///
    /// # Returns
    /// - `Ok(true)` — proposal was produced and broadcast.
    /// - `Ok(false)` — preconditions not met (wrong step, not proposer, etc.).
    ///   When [`ProducerConfig::strict_preconditions`] is `true`, this path is
    ///   instead reported as an `Err(ProducerError::NotInProposeStep | …)`.
    /// - `Err(e)` — a fatal error occurred during production.
    ///
    /// # Preconditions (checked in order)
    /// 1. Engine must be in the `Propose` step.
    /// 2. No proposal must already exist for this round.
    /// 3. The local node must be the designated proposer.
    pub fn try_produce<V, S, B, O>(
        &self,
        engine: &mut crate::consensus::Engine<V>,
        signer: &S,
        store: &B,
        out: &mut O,
        txs: Vec<Tx>,
        econ_params: &EconomicsParams,
    ) -> ProducerResult<bool>
    where
        V: crate::crypto::Verifier,
        S: Signer,
        B: crate::consensus::BlockStore,
        O: Outbox,
    {
        // ── Precondition 1: Correct step ──────────────────────────────────
        if engine.state.step != Step::Propose {
            debug!(
                step = ?engine.state.step,
                "not in propose step, skipping proposal"
            );
            return self.precondition_failure(
                ProducerError::NotInProposeStep { step: engine.state.step },
            );
        }

        // ── Precondition 2: No existing proposal ──────────────────────────
        if engine.state.proposal.is_some() {
            debug!(
                round = engine.state.round,
                "proposal already exists for this round"
            );
            return self.precondition_failure(ProducerError::ProposalAlreadyExists {
                round: engine.state.round,
            });
        }

        // ── Precondition 3: Designated proposer ───────────────────────────
        if !engine.is_proposer(&signer.public_key()) {
            debug!(
                height = engine.state.height,
                round = engine.state.round,
                "not the designated proposer"
            );
            return self.precondition_failure(ProducerError::NotProposer {
                height: engine.state.height,
                round: engine.state.round,
            });
        }

        // ── All preconditions met — produce the block ─────────────────────
        info!(
            height = engine.state.height,
            round = engine.state.round,
            max_txs = self.cfg.max_txs,
            max_gas = self.cfg.max_gas_per_block,
            "producing proposal"
        );

        // Derive proposer address (fallible: bad public key length).
        let proposer_addr = Self::proposer_address(signer)?;

        // Bounded, gas-aware transaction selection.
        let input_len = txs.len();
        let mut txs_to_include: Vec<Tx> = Vec::with_capacity(self.cfg.max_txs.min(input_len));
        let mut total_gas: u64 = 0;

        for tx in txs.into_iter().take(self.cfg.max_txs) {
            let intrinsic_gas = crate::execution::intrinsic_gas(&tx);
            // Use checked_add so a malformed intrinsic gas cannot overflow
            // the running total and silently accept a huge tx.
            let next = match total_gas.checked_add(intrinsic_gas) {
                Some(v) => v,
                None => {
                    warn!(
                        running = total_gas,
                        intrinsic = intrinsic_gas,
                        "intrinsic gas overflow; stopping selection"
                    );
                    break;
                }
            };
            if next > self.cfg.max_gas_per_block {
                trace!(
                    running = total_gas,
                    intrinsic = intrinsic_gas,
                    cap = self.cfg.max_gas_per_block,
                    "gas cap reached; stopping selection"
                );
                break;
            }
            txs_to_include.push(tx);
            total_gas = next;
        }

        let tx_count = txs_to_include.len();
        if input_len > self.cfg.max_txs {
            debug!(
                input = input_len,
                included = tx_count,
                max_txs = self.cfg.max_txs,
                "mempool batch truncated to max_txs"
            );
        }

        info!(
            height = engine.state.height,
            round = engine.state.round,
            tx_count = tx_count,
            total_gas = total_gas,
            "selected transactions for block"
        );

        // Build the block.
        let (block, next_state, receipts) = build_block(
            engine.state.height,
            engine.state.round,
            engine.prev_block_id.clone(),
            signer.public_key().0.clone(),
            &proposer_addr,
            &engine.app_state,
            engine.base_fee_per_gas,
            econ_params,
            txs_to_include,
            self.cfg.max_gas_per_block,
        );

        let block_id = block.id();
        // Capture fields we need after `block` is moved into engine state.
        let gas_used = block.header.gas_used;
        let state_root = block.header.state_root;

        debug!(
            block_id = %hex::encode(&block_id.0[..8]),
            tx_count = tx_count,
            state_root = %hex::encode(&state_root.0[..8]),
            "block built"
        );

        // Persist the block BEFORE mutating engine state, so a store failure
        // leaves consensus state unchanged.
        store
            .put(block.clone())
            .map_err(|e| ProducerError::BlockStoreError {
                reason: format!("failed to store block: {}", e),
            })?;

        // Update engine state only after the block is safely stored.
        engine.app_state = next_state;
        engine.base_fee_per_gas = crate::execution::next_base_fee(
            engine.base_fee_per_gas,
            gas_used,
            econ_params.gas_target,
        );

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

        // Update engine state (move the block; only the proposal clone remains).
        engine.state.proposal = Some(proposal.clone());
        engine.state.proposal_block = Some(block);

        // Commit receipts to block store if supported. Receipt persistence is
        // best-effort — a failure here should not abort the proposal, because
        // the block itself is already durable and votes may already be in flight.
        if let Err(e) = store.put_receipts(&block_id, receipts) {
            warn!(error = %e, "failed to store receipts");
        }

        // Broadcast.
        out.broadcast(ConsensusMsg::Proposal(proposal));

        info!(
            height = engine.state.height,
            round = engine.state.round,
            block_id = %hex::encode(&block_id.0[..8]),
            tx_count = tx_count,
            gas_used = gas_used,
            "proposal broadcast"
        );

        Ok(true)
    }

    /// Convert a precondition error into either `Ok(false)` (default) or
    /// `Err(e)` (strict mode).
    #[inline]
    fn precondition_failure(&self, err: ProducerError) -> ProducerResult<bool> {
        if self.cfg.strict_preconditions {
            Err(err)
        } else {
            Ok(false)
        }
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
    use std::collections::HashMap;
    use std::sync::Mutex;

    // ── Mock implementations ────────────────────────────────────────────
    //
    // NOTE: `put` and `put_receipts` return `Result` to match the production
    // `BlockStore` trait — the previous version returned `()` and would not
    // compile against `try_produce`.

    /// Error type used by the in-memory block store. Replaced with the real
    /// `crate::consensus::BlockStoreError` in production code.
    type MockStoreError = String;

    struct MockBlockStore {
        blocks: Mutex<HashMap<Hash32, crate::types::Block>>,
        receipts: Mutex<HashMap<Hash32, Vec<crate::types::Receipt>>>,
    }

    impl MockBlockStore {
        fn new() -> Self {
            Self {
                blocks: Mutex::new(HashMap::new()),
                receipts: Mutex::new(HashMap::new()),
            }
        }
        fn stored_count(&self) -> usize {
            self.blocks.lock().unwrap().len()
        }
        fn receipt_count(&self) -> usize {
            self.receipts.lock().unwrap().len()
        }
    }

    impl crate::consensus::BlockStore for MockBlockStore {
        fn get(&self, id: &Hash32) -> Option<crate::types::Block> {
            self.blocks.lock().unwrap().get(id).cloned()
        }
        fn put(&self, block: crate::types::Block) -> Result<(), MockStoreError> {
            self.blocks.lock().unwrap().insert(block.id(), block);
            Ok(())
        }
        fn put_receipts(
            &self,
            block_id: &Hash32,
            receipts: Vec<crate::types::Receipt>,
        ) -> Result<(), MockStoreError> {
            self.receipts.lock().unwrap().insert(*block_id, receipts);
            Ok(())
        }
    }

    struct MockOutbox {
        broadcasts: Mutex<Vec<ConsensusMsg>>,
    }

    impl MockOutbox {
        fn new() -> Self {
            Self { broadcasts: Mutex::new(Vec::new()) }
        }
        fn proposal_count(&self) -> usize {
            self.broadcasts
                .lock()
                .unwrap()
                .iter()
                .filter(|m| matches!(m, ConsensusMsg::Proposal(_)))
                .count()
        }
        fn last_proposal(&self) -> Option<Proposal> {
            self.broadcasts
                .lock()
                .unwrap()
                .iter()
                .rev()
                .find_map(|msg| match msg {
                    ConsensusMsg::Proposal(p) => Some(p.clone()),
                    _ => None,
                })
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

    // ── Helpers ─────────────────────────────────────────────────────────

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

    fn make_tx(nonce: u64) -> Tx {
        Tx {
            pubkey: vec![0; 32],
            from: format!("sender{}", nonce),
            nonce,
            max_fee_per_gas: 100,
            max_priority_fee_per_gas: 10,
            gas_limit: 100_000,
            payload: format!("set key{} val{}", nonce, nonce),
            signature: vec![0; 64],
            chain_id: 1,
        }
    }

    fn default_econ_params() -> EconomicsParams {
        EconomicsParams {
            gas_target: 15_000_000,
            ..Default::default()
        }
    }

    // ── Configuration tests ─────────────────────────────────────────────
    #[test]
    fn test_config_valid() {
        let cfg = ProducerConfig::default();
        assert!(cfg.validate().is_ok());
    }

    #[test]
    fn test_config_zero_max_txs() {
        let cfg = ProducerConfig { max_txs: 0, ..Default::default() };
        assert!(matches!(
            cfg.validate(),
            Err(ProducerError::InvalidMaxTxs { .. })
        ));
    }

    #[test]
    fn test_config_excessive_max_txs() {
        let cfg = ProducerConfig {
            max_txs: MAX_ALLOWED_TXS + 1,
            ..Default::default()
        };
        assert!(matches!(
            cfg.validate(),
            Err(ProducerError::InvalidMaxTxs { .. })
        ));
    }

    #[test]
    fn test_config_zero_gas() {
        let cfg = ProducerConfig {
            max_gas_per_block: 0,
            ..Default::default()
        };
        // Regression: previously returned InvalidMaxTxs (wrong variant).
        assert_eq!(cfg.validate(), Err(ProducerError::InvalidMaxGas));
    }

    #[test]
    fn test_producer_creation_with_invalid_config() {
        let cfg = ProducerConfig { max_txs: 0, ..Default::default() };
        assert!(SimpleBlockProducer::new(cfg).is_err());
    }

    // ── Production tests ────────────────────────────────────────────────
    #[test]
    fn test_producer_proposes_when_proposer() {
        let signer = Ed25519Keypair::from_seed([1u8; 32]);
        let mut engine = make_engine(&signer);
        let store = MockBlockStore::new();
        let mut outbox = MockOutbox::new();
        let producer = SimpleBlockProducer::new(ProducerConfig::default()).unwrap();

        assert_eq!(engine.state.step, Step::Propose);
        assert!(engine.state.proposal.is_none());

        let econ_params = default_econ_params();
        let result = producer
            .try_produce(&mut engine, &signer, &store, &mut outbox, vec![], &econ_params)
            .unwrap();

        assert!(result);
        assert!(engine.state.proposal.is_some());
        assert!(engine.state.proposal_block.is_some());
        assert_eq!(store.stored_count(), 1);
        assert_eq!(store.receipt_count(), 1);
        assert_eq!(outbox.proposal_count(), 1);

        let proposal = outbox.last_proposal().unwrap();
        assert_eq!(proposal.height, 1);
        assert_eq!(proposal.round, 0);
        assert_eq!(proposal.proposer, signer.public_key());
        assert!(proposal.block.is_some());
    }

    #[test]
    fn test_producer_skips_when_not_proposer() {
        let proposer = Ed25519Keypair::from_seed([1u8; 32]);
        let non_proposer = Ed25519Keypair::from_seed([2u8; 32]);
        let mut engine = make_engine(&proposer);
        let store = MockBlockStore::new();
        let mut outbox = MockOutbox::new();
        let producer = SimpleBlockProducer::new(ProducerConfig::default()).unwrap();

        let econ_params = default_econ_params();
        let result = producer
            .try_produce(
                &mut engine,
                &non_proposer,
                &store,
                &mut outbox,
                vec![],
                &econ_params,
            )
            .unwrap();

        assert!(!result);
        assert!(engine.state.proposal.is_none());
        assert_eq!(store.stored_count(), 0);
        assert_eq!(outbox.proposal_count(), 0);
    }

    #[test]
    fn test_producer_strict_returns_not_proposer_error() {
        let proposer = Ed25519Keypair::from_seed([1u8; 32]);
        let non_proposer = Ed25519Keypair::from_seed([2u8; 32]);
        let mut engine = make_engine(&proposer);
        let store = MockBlockStore::new();
        let mut outbox = MockOutbox::new();
        let cfg = ProducerConfig {
            strict_preconditions: true,
            ..Default::default()
        };
        let producer = SimpleBlockProducer::new(cfg).unwrap();

        let err = producer
            .try_produce(
                &mut engine,
                &non_proposer,
                &store,
                &mut outbox,
                vec![],
                &default_econ_params(),
            )
            .unwrap_err();
        assert!(matches!(err, ProducerError::NotProposer { height: 1, .. }));
    }

    #[test]
    fn test_producer_skips_when_proposal_exists() {
        let signer = Ed25519Keypair::from_seed([1u8; 32]);
        let mut engine = make_engine(&signer);
        let store = MockBlockStore::new();
        let mut outbox = MockOutbox::new();
        let producer = SimpleBlockProducer::new(ProducerConfig::default()).unwrap();
        let econ_params = default_econ_params();

        let first = producer
            .try_produce(&mut engine, &signer, &store, &mut outbox, vec![], &econ_params)
            .unwrap();
        assert!(first);

        let second = producer
            .try_produce(&mut engine, &signer, &store, &mut outbox, vec![], &econ_params)
            .unwrap();
        assert!(!second);
        assert_eq!(outbox.proposal_count(), 1);
    }

    #[test]
    fn test_producer_respects_max_txs() {
        let signer = Ed25519Keypair::from_seed([1u8; 32]);
        let mut engine = make_engine(&signer);
        let store = MockBlockStore::new();
        let mut outbox = MockOutbox::new();
        let cfg = ProducerConfig {
            max_txs: 3,
            include_block_in_proposal: true,
            ..Default::default()
        };
        let producer = SimpleBlockProducer::new(cfg).unwrap();

        let txs: Vec<Tx> = (0..10).map(make_tx).collect();
        let result = producer
            .try_produce(
                &mut engine,
                &signer,
                &store,
                &mut outbox,
                txs,
                &default_econ_params(),
            )
            .unwrap();

        assert!(result);
        let proposal = outbox.last_proposal().unwrap();
        let block = proposal.block.as_ref().unwrap();
        assert_eq!(block.txs.len(), 3);
    }

    #[test]
    fn test_producer_respects_max_gas() {
        let signer = Ed25519Keypair::from_seed([1u8; 32]);
        let mut engine = make_engine(&signer);
        let store = MockBlockStore::new();
        let mut outbox = MockOutbox::new();
        let cfg = ProducerConfig {
            max_txs: 100,
            max_gas_per_block: 50_000,
            include_block_in_proposal: true,
            ..Default::default()
        };
        let producer = SimpleBlockProducer::new(cfg).unwrap();

        let txs: Vec<Tx> = (0..10).map(make_tx).collect();
        let result = producer
            .try_produce(
                &mut engine,
                &signer,
                &store,
                &mut outbox,
                txs,
                &default_econ_params(),
            )
            .unwrap();

        assert!(result);
        let proposal = outbox.last_proposal().unwrap();
        let block = proposal.block.as_ref().unwrap();
        assert!(block.txs.len() <= 2);
        assert!(block.header.gas_used <= 50_000);
    }

    #[test]
    fn test_producer_with_empty_txs() {
        let signer = Ed25519Keypair::from_seed([1u8; 32]);
        let mut engine = make_engine(&signer);
        let store = MockBlockStore::new();
        let mut outbox = MockOutbox::new();
        let producer = SimpleBlockProducer::new(ProducerConfig::default()).unwrap();

        let result = producer
            .try_produce(
                &mut engine,
                &signer,
                &store,
                &mut outbox,
                vec![],
                &default_econ_params(),
            )
            .unwrap();

        assert!(result);
        let proposal = outbox.last_proposal().unwrap();
        let block = proposal.block.as_ref().unwrap();
        assert_eq!(block.txs.len(), 0);
    }

    #[test]
    fn test_proposer_address_derivation() {
        let signer = Ed25519Keypair::from_seed([42u8; 32]);
        let addr = SimpleBlockProducer::proposer_address(&signer).unwrap();
        assert_eq!(addr.len(), 40);
        assert!(addr.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn test_proposer_address_deterministic() {
        let signer = Ed25519Keypair::from_seed([99u8; 32]);
        let addr1 = SimpleBlockProducer::proposer_address(&signer).unwrap();
        let addr2 = SimpleBlockProducer::proposer_address(&signer).unwrap();
        assert_eq!(addr1, addr2);
    }

    #[test]
    fn test_is_proposer() {
        let proposer = Ed25519Keypair::from_seed([1u8; 32]);
        let non_proposer = Ed25519Keypair::from_seed([2u8; 32]);
        let engine = make_engine(&proposer);
        let producer = SimpleBlockProducer::new(ProducerConfig::default()).unwrap();

        assert!(producer.is_proposer(&engine, &proposer));
        assert!(!producer.is_proposer(&engine, &non_proposer));
    }

    #[test]
    fn test_producer_updates_engine_state() {
        let signer = Ed25519Keypair::from_seed([1u8; 32]);
        let mut engine = make_engine(&signer);
        let store = MockBlockStore::new();
        let mut outbox = MockOutbox::new();
        let producer = SimpleBlockProducer::new(ProducerConfig::default()).unwrap();

        let old_base_fee = engine.base_fee_per_gas;
        let result = producer
            .try_produce(
                &mut engine,
                &signer,
                &store,
                &mut outbox,
                vec![],
                &default_econ_params(),
            )
            .unwrap();

        assert!(result);
        assert!(engine.state.proposal.is_some());
        assert!(engine.state.proposal_block.is_some());
        assert!(engine.base_fee_per_gas <= old_base_fee);
    }
}
