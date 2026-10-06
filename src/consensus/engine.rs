//! Quantum Consensus Engine for IONA — Hamiltonian-based BFT state machine.
//!
//! # Model
//!
//! The consensus engine is a classical BFT state machine (Tendermint-style
//! Propose → Prevote → Precommit → Commit) with a lightweight **decoherence
//! scoreboard** used purely for observability. The "quantum" naming reflects
//! the conceptual framing (steps as projective measurements, timeouts as
//! Lindblad decoherence); the actual safety and liveness guarantees come from
//! the classical vote-tally and lock rules.
//!
//! ## What is *guaranteed*
//!
//! - **Safety**: at most one block commits per height. Two conflicting
//!   precommit quorums at the same height would require ≥1/3 Byzantine
//!   validators (standard BFT assumption).
//! - **No equivocation**: every `Proposal`/`Vote` we sign is durably recorded
//!   via [`DoubleSignGuard`] **before** the signature is produced.
//! - **Determinism**: given the same inputs and a fixed validator set, the
//!   engine reaches the same decisions.
//!
//! ## What is *informational only*
//!
//! - `QuantumConsensusState` (purity, entropy, coherence). These values decay
//!   with activity, never gate any consensus decision, and never cause an
//!   error. A `warn!` is emitted when coherence crosses
//!   [`MIN_CONSENSUS_COHERENCE`]; the node continues to operate normally.
//!
//! # Double-sign ordering
//!
//! The contract for [`DoubleSignGuard`] is:
//!
//! 1. `check_*` — read-only, safe to call speculatively.
//! 2. `record_*` — durable, must succeed before signing.
//! 3. `sign` — produce the signature.
//! 4. Broadcast.
//!
//! This module follows that order **exactly**. If `record_*` fails, no
//! signature is produced and nothing is broadcast.
//!
//! # Concurrency
//!
//! `Engine` is `Send` when `V: Verifier + Send`, but not `Sync` — it mutates
//! its own state and expects single-threaded driving from the consensus loop.

use crate::consensus::double_sign::DoubleSignGuard;
use crate::consensus::messages::*;
use crate::consensus::quorum::*;
use crate::consensus::validator_set::*;
use crate::crypto::{PublicKeyBytes, Signer, Verifier};
use crate::evidence::Evidence;
use crate::execution::{build_block, next_base_fee, verify_block_with_vset, KvState};
use crate::slashing::StakeLedger;
use crate::types::{Block, Hash32, Height, Receipt, Round, Tx};
use std::collections::{BTreeMap, HashMap};
use thiserror::Error;
use tracing::{info, warn};

// -----------------------------------------------------------------------------
// Quantum Constants (informational)
// -----------------------------------------------------------------------------

/// Decoherence rate per consensus step transition.
const STEP_DECOHERENCE_RATE: f64 = 0.0001;

/// Decoherence rate per timeout tick.
const TIMEOUT_DECOHERENCE_RATE: f64 = 0.0005;

/// Decoherence per successful quorum measurement.
///
/// Small, since a quorum is a "normal" event. The original code used
/// `1/sqrt(KRAUS_RANK)` = 0.5, which collapsed coherence to ~0 after four
/// quorums and made `is_healthy` permanently false.
const QUORUM_DECOHERENCE_RATE: f64 = 0.001;

/// Emit a `warn!` when coherence drops below this threshold. This is purely
/// an observability signal — it does not gate consensus.
const MIN_CONSENSUS_COHERENCE: f64 = 0.9;

// -----------------------------------------------------------------------------
// Quantum Consensus State (observability only)
// -----------------------------------------------------------------------------

/// Decoherence scoreboard for the consensus engine.
///
/// **This does not gate any decision.** It exists so operators can observe
/// long-running decoherence trends and correlate them with network events.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq)]
pub struct QuantumConsensusState {
    /// Purity γ = Tr(ρ²), in [0, 1].
    pub purity: f64,
    /// Informational von Neumann entropy proxy, ≥ 0.
    pub entropy: f64,
    /// Coherence of the current step, in [0, 1].
    pub step_coherence: f64,
    /// Entanglement fidelity with the validator set, in [0, 1].
    pub validator_entanglement: f64,
    /// Total step transitions performed.
    pub total_transitions: u64,
    /// Total quorum measurements performed.
    pub total_quorums: u64,
    /// Total timeouts experienced.
    pub total_timeouts: u64,
    /// Whether coherence is above [`MIN_CONSENSUS_COHERENCE`].
    /// **Informational only.**
    pub is_healthy: bool,
}

impl QuantumConsensusState {
    /// Ground state |∅⟩ — fully coherent.
    pub fn new() -> Self {
        Self {
            purity: 1.0,
            entropy: 0.0,
            step_coherence: 1.0,
            validator_entanglement: 1.0,
            total_transitions: 0,
            total_quorums: 0,
            total_timeouts: 0,
            is_healthy: true,
        }
    }

    fn apply_step_decoherence(&mut self) {
        self.total_transitions = self.total_transitions.saturating_add(1);
        let decay = (-STEP_DECOHERENCE_RATE).exp();
        self.step_coherence = (self.step_coherence * decay).clamp(0.0, 1.0);
        self.validator_entanglement =
            (self.validator_entanglement * decay.sqrt()).clamp(0.0, 1.0);
        self.recompute();
    }

    fn apply_timeout_decoherence(&mut self) {
        self.total_timeouts = self.total_timeouts.saturating_add(1);
        let decay = (-TIMEOUT_DECOHERENCE_RATE).exp();
        self.step_coherence = (self.step_coherence * decay).clamp(0.0, 1.0);
        self.recompute();
    }

    fn apply_quorum_decoherence(&mut self) {
        self.total_quorums = self.total_quorums.saturating_add(1);
        let decay = (-QUORUM_DECOHERENCE_RATE).exp();
        self.step_coherence = (self.step_coherence * decay).clamp(0.0, 1.0);
        self.recompute();
    }

    fn recompute(&mut self) {
        self.purity = (self.step_coherence * self.validator_entanglement).clamp(0.0, 1.0);
        self.entropy = if self.purity >= 1.0 {
            0.0
        } else {
            // -p·ln(p), a monotone proxy for mixedness.
            -(self.purity * self.purity.ln().min(0.0))
        };
        let was_healthy = self.is_healthy;
        self.is_healthy = self.purity >= MIN_CONSENSUS_COHERENCE;
        if was_healthy && !self.is_healthy {
            warn!(
                purity = self.purity,
                threshold = MIN_CONSENSUS_COHERENCE,
                "consensus coherence below threshold (informational)"
            );
        }
    }
}

impl Default for QuantumConsensusState {
    fn default() -> Self {
        Self::new()
    }
}

// -----------------------------------------------------------------------------
// Errors
// -----------------------------------------------------------------------------

/// Consensus errors.
#[derive(Debug, Error)]
pub enum ConsensusError {
    #[error("invalid message signature")]
    BadSig,
    #[error("unknown validator")]
    UnknownValidator,
    #[error("invalid height/round")]
    BadStep,
    #[error("execution error")]
    Exec,
    #[error("engine already decided at this height")]
    AlreadyDecided,
}

// -----------------------------------------------------------------------------
// Step
// -----------------------------------------------------------------------------

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub enum Step {
    Propose,
    Prevote,
    Precommit,
    Commit,
}

// -----------------------------------------------------------------------------
// Commit certificate
// -----------------------------------------------------------------------------

#[derive(Clone, Debug, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct CommitCertificate {
    pub height: Height,
    pub block_id: Hash32,
    pub precommits: Vec<Vote>,
}

// -----------------------------------------------------------------------------
// Configuration
// -----------------------------------------------------------------------------

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Config {
    pub propose_timeout_ms: u64,
    pub prevote_timeout_ms: u64,
    pub precommit_timeout_ms: u64,
    pub max_rounds: u32,
    pub max_txs_per_block: usize,
    pub gas_target: u64,
    pub initial_base_fee_per_gas: u64,
    pub include_block_in_proposal: bool,
    /// If true, advance step immediately when quorum is reached (don't wait for timeout).
    pub fast_quorum: bool,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            propose_timeout_ms: 300,
            prevote_timeout_ms: 200,
            precommit_timeout_ms: 200,
            max_rounds: 50,
            max_txs_per_block: 4096,
            gas_target: 43_000_000,
            initial_base_fee_per_gas: 1,
            include_block_in_proposal: true,
            fast_quorum: true,
        }
    }
}

impl Config {
    /// Validate configuration parameters.
    pub fn validate(&self) -> Result<(), String> {
        if self.propose_timeout_ms == 0 {
            return Err("propose_timeout_ms must be > 0".into());
        }
        if self.prevote_timeout_ms == 0 {
            return Err("prevote_timeout_ms must be > 0".into());
        }
        if self.precommit_timeout_ms == 0 {
            return Err("precommit_timeout_ms must be > 0".into());
        }
        if self.max_rounds == 0 {
            return Err("max_rounds must be > 0".into());
        }
        if self.max_txs_per_block == 0 {
            return Err("max_txs_per_block must be > 0".into());
        }
        if self.gas_target == 0 {
            return Err("gas_target must be > 0".into());
        }
        if self.initial_base_fee_per_gas == 0 {
            return Err("initial_base_fee_per_gas must be > 0".into());
        }
        Ok(())
    }
}

// -----------------------------------------------------------------------------
// Consensus state
// -----------------------------------------------------------------------------

#[derive(Clone, Debug, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct ConsensusState {
    pub height: Height,
    pub round: Round,
    pub step: Step,

    pub locked_round: Option<Round>,
    pub locked_value: Option<Hash32>,

    pub valid_round: Option<Round>,
    pub valid_value: Option<Hash32>,

    pub proposal: Option<Proposal>,
    pub proposal_block: Option<Block>,

    pub votes: HashMap<Round, HashMap<VoteType, HashMap<PublicKeyBytes, Vote>>>,
    pub vote_index: BTreeMap<(PublicKeyBytes, Height, Round, VoteType), (Option<Hash32>, Vote)>,

    pub decided: Option<CommitCertificate>,

    /// Informational decoherence scoreboard.
    #[serde(default)]
    pub quantum: QuantumConsensusState,
}

impl ConsensusState {
    pub fn new(height: Height) -> Self {
        Self {
            height,
            round: 0,
            step: Step::Propose,
            locked_round: None,
            locked_value: None,
            valid_round: None,
            valid_value: None,
            proposal: None,
            proposal_block: None,
            votes: HashMap::new(),
            vote_index: BTreeMap::new(),
            decided: None,
            quantum: QuantumConsensusState::new(),
        }
    }

    #[must_use]
    pub fn purity(&self) -> f64 {
        self.quantum.purity
    }

    #[must_use]
    pub fn is_quantum_healthy(&self) -> bool {
        self.quantum.is_healthy
    }
}

// -----------------------------------------------------------------------------
// Traits
// -----------------------------------------------------------------------------

pub trait BlockStore: Send + Sync {
    fn get(&self, id: &Hash32) -> Option<Block>;
    fn put(&self, block: Block);
}

pub trait Outbox {
    fn broadcast(&mut self, msg: ConsensusMsg);
    fn request_block(&mut self, block_id: Hash32);
    fn on_commit(
        &mut self,
        cert: &CommitCertificate,
        block: &Block,
        new_state: &KvState,
        new_base_fee: u64,
        receipts: &[Receipt],
    );
}

// -----------------------------------------------------------------------------
// Engine
// -----------------------------------------------------------------------------

pub struct Engine<V: Verifier> {
    pub cfg: Config,
    pub vset: ValidatorSet,
    pub state: ConsensusState,

    pub prev_block_id: Hash32,
    pub app_state: KvState,

    pub stakes: StakeLedger,
    pub base_fee_per_gas: u64,

    /// Persisted double-sign protection.
    ds_guard: Option<DoubleSignGuard>,

    step_elapsed_ms: u64,
    _v: std::marker::PhantomData<V>,
}

impl<V: Verifier> Engine<V> {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        cfg: Config,
        vset: ValidatorSet,
        height: Height,
        prev_block_id: Hash32,
        app_state: KvState,
        stakes: StakeLedger,
        ds_guard: Option<DoubleSignGuard>,
    ) -> Self {
        Self {
            base_fee_per_gas: cfg.initial_base_fee_per_gas,
            cfg,
            vset,
            state: ConsensusState::new(height),
            prev_block_id,
            app_state,
            stakes,
            step_elapsed_ms: 0,
            ds_guard,
            _v: std::marker::PhantomData,
        }
    }

    // ── Quantum accessors (informational) ────────────────────────────────

    #[must_use]
    pub fn purity(&self) -> f64 {
        self.state.quantum.purity
    }

    #[must_use]
    pub fn entropy(&self) -> f64 {
        self.state.quantum.entropy
    }

    #[must_use]
    pub fn is_quantum_healthy(&self) -> bool {
        self.state.quantum.is_healthy
    }

    #[must_use]
    pub fn quantum_stats(&self) -> &QuantumConsensusState {
        &self.state.quantum
    }

    /// Whether this height has been decided.
    #[must_use]
    pub fn is_decided(&self) -> bool {
        self.state.decided.is_some()
    }

    // ── Classical helpers ────────────────────────────────────────────────

    #[must_use]
    pub fn is_proposer(&self, pk: &PublicKeyBytes) -> bool {
        self.vset
            .proposer_for(self.state.height, self.state.round)
            .pk
            == *pk
    }

    fn proposer_addr_string(&self, pk: &PublicKeyBytes) -> String {
        hex::encode(&blake3::hash(&pk.0).as_bytes()[..20])
    }

    // ── Tick ─────────────────────────────────────────────────────────────

    /// Advance the state machine by `dt_ms` milliseconds.
    ///
    /// `dt_ms` should be > 0. Passing 0 is accepted but may cause the
    /// propose-on-first-tick heuristic to fire every call.
    pub fn tick<S: Signer, B: BlockStore, O: Outbox>(
        &mut self,
        signer: &S,
        store: &B,
        out: &mut O,
        dt_ms: u64,
        mempool_drain: impl FnOnce(usize) -> Vec<Tx>,
    ) {
        if self.state.decided.is_some() {
            return;
        }
        self.step_elapsed_ms = self.step_elapsed_ms.saturating_add(dt_ms);

        match self.state.step {
            Step::Propose => {
                // First tick after entering Propose: attempt to propose.
                // (`step_elapsed_ms` was reset to 0 on entry, so after adding
                // `dt_ms` it equals `dt_ms` exactly once — assuming `dt_ms > 0`.)
                let first_tick = self.step_elapsed_ms == dt_ms;
                if first_tick && self.state.proposal.is_none() {
                    self.maybe_propose(signer, store, out, mempool_drain);
                }

                let has_valid_proposal = self.cfg.fast_quorum
                    && self.state.proposal.is_some()
                    && self.state.proposal_block.is_some();

                if has_valid_proposal || self.step_elapsed_ms >= self.cfg.propose_timeout_ms {
                    if !has_valid_proposal {
                        self.state.quantum.apply_timeout_decoherence();
                    }
                    self.state.quantum.apply_step_decoherence();
                    self.state.step = Step::Prevote;
                    self.step_elapsed_ms = 0;

                    // Prevote for the proposal only if we actually have the block.
                    let vote_block = if has_valid_proposal {
                        self.state.proposal.as_ref().map(|p| p.block_id.clone())
                    } else {
                        None
                    };
                    self.broadcast_vote(signer, out, VoteType::Prevote, vote_block);
                }
            }
            Step::Prevote => {
                if self.step_elapsed_ms >= self.cfg.prevote_timeout_ms {
                    self.state.quantum.apply_timeout_decoherence();
                    self.advance_round(signer, store, out);
                }
            }
            Step::Precommit => {
                if self.step_elapsed_ms >= self.cfg.precommit_timeout_ms {
                    self.state.quantum.apply_timeout_decoherence();
                    self.advance_round(signer, store, out);
                }
            }
            Step::Commit => {}
        }
    }

    fn advance_round<S: Signer, B: BlockStore, O: Outbox>(
        &mut self,
        signer: &S,
        store: &B,
        out: &mut O,
    ) {
        // `max_rounds = N` allows rounds 0..N-1; round N triggers the guard.
        if self.state.round + 1 >= self.cfg.max_rounds {
            warn!(
                height = self.state.height,
                round = self.state.round,
                max_rounds = self.cfg.max_rounds,
                "max rounds reached; staying in current round"
            );
            return;
        }
        self.state.round += 1;
        self.state.proposal = None;
        self.state.proposal_block = None;
        self.state.step = Step::Propose;
        self.step_elapsed_ms = 0;
        self.state.quantum.apply_step_decoherence();
        info!(
            height = self.state.height,
            round = self.state.round,
            "advance round"
        );
        self.maybe_propose(signer, store, out, |_| vec![]);
    }

    fn maybe_propose<S: Signer, B: BlockStore, O: Outbox>(
        &mut self,
        signer: &S,
        store: &B,
        out: &mut O,
        mempool_drain: impl FnOnce(usize) -> Vec<Tx>,
    ) {
        if self.state.proposal.is_some() {
            return;
        }
        if !self.is_proposer(&signer.public_key()) {
            return;
        }

        let txs = mempool_drain(self.cfg.max_txs_per_block);
        let proposer_addr = self.proposer_addr_string(&signer.public_key());
        let (block, _next_state, _receipts) = build_block(
            self.state.height,
            self.state.round,
            self.prev_block_id.clone(),
            signer.public_key().0.clone(),
            &proposer_addr,
            &self.app_state,
            self.base_fee_per_gas,
            txs,
        );
        let bid = block.id();

        // ── Double-sign protocol: check → record → sign → store → broadcast ──
        //
        // The order matters. `record_*` MUST succeed before we produce a
        // signature; otherwise a crash between sign and record would allow
        // signing a different block for the same (height, round) on restart.
        if let Some(g) = &self.ds_guard {
            if let Err(e) = g.check_proposal(self.state.height, self.state.round, &bid) {
                warn!(error = %e, "double-sign guard refused proposal signature");
                self.state.quantum.apply_step_decoherence();
                return;
            }
            if let Err(e) = g.record_proposal(self.state.height, self.state.round, &bid) {
                warn!(error = %e, "double-sign guard write failed — halting proposal");
                self.state.quantum.apply_step_decoherence();
                return;
            }
        }

        let sign_bytes = proposal_sign_bytes(
            self.state.height,
            self.state.round,
            &bid,
            self.state.valid_round,
        );
        let sig = signer.sign(&sign_bytes);

        // Store only after we've committed to signing this block.
        store.put(block.clone());

        let prop = Proposal {
            height: self.state.height,
            round: self.state.round,
            proposer: signer.public_key(),
            block_id: bid.clone(),
            block: if self.cfg.include_block_in_proposal {
                Some(block.clone())
            } else {
                None
            },
            pol_round: self.state.valid_round,
            signature: sig,
        };

        self.state.proposal = Some(prop.clone());
        self.state.proposal_block = Some(block);

        self.state.quantum.apply_step_decoherence();
        out.broadcast(ConsensusMsg::Proposal(prop));
        info!(
            height = self.state.height,
            round = self.state.round,
            "broadcast proposal"
        );
    }

    // ── Message handling ─────────────────────────────────────────────────

    pub fn on_message<S: Signer, B: BlockStore, O: Outbox>(
        &mut self,
        signer: &S,
        store: &B,
        out: &mut O,
        msg: ConsensusMsg,
    ) -> Result<(), ConsensusError> {
        match msg {
            ConsensusMsg::Proposal(p) => self.on_proposal(signer, store, out, p),
            ConsensusMsg::Vote(v) => self.on_vote(signer, store, out, v),
            ConsensusMsg::Evidence(ev) => {
                self.stakes.apply_evidence(&ev, self.state.height);
                self.state.quantum.apply_step_decoherence();
                Ok(())
            }
        }
    }

    fn verify_proposal(&self, p: &Proposal) -> Result<(), ConsensusError> {
        if !self.vset.contains(&p.proposer) {
            return Err(ConsensusError::UnknownValidator);
        }
        if self.vset.proposer_for(p.height, p.round).pk != p.proposer {
            return Err(ConsensusError::UnknownValidator);
        }
        if p.height != self.state.height || p.round != self.state.round {
            return Err(ConsensusError::BadStep);
        }
        let bytes = proposal_sign_bytes(p.height, p.round, &p.block_id, p.pol_round);
        V::verify(&p.proposer, &bytes, &p.signature).map_err(|_| ConsensusError::BadSig)?;
        Ok(())
    }

    fn verify_vote(&self, v: &Vote) -> Result<(), ConsensusError> {
        if !self.vset.contains(&v.voter) {
            return Err(ConsensusError::UnknownValidator);
        }
        if v.height != self.state.height || v.round != self.state.round {
            return Err(ConsensusError::BadStep);
        }
        let bytes = vote_sign_bytes(v.vote_type, v.height, v.round, &v.block_id);
        V::verify(&v.voter, &bytes, &v.signature).map_err(|_| ConsensusError::BadSig)?;
        Ok(())
    }

    fn on_proposal<S: Signer, B: BlockStore, O: Outbox>(
        &mut self,
        signer: &S,
        store: &B,
        out: &mut O,
        p: Proposal,
    ) -> Result<(), ConsensusError> {
        if self.state.decided.is_some() {
            return Ok(());
        }
        self.verify_proposal(&p)?;

        // Cache the inline block if the proposal carries one.
        if let Some(b) = p.block.clone() {
            store.put(b);
        }

        let block = match store.get(&p.block_id) {
            Some(b) => b,
            None => {
                // We don't have the block yet: prevote NIL and request it.
                out.request_block(p.block_id.clone());
                self.state.step = Step::Prevote;
                self.step_elapsed_ms = 0;
                self.state.quantum.apply_step_decoherence();
                self.broadcast_vote(signer, out, VoteType::Prevote, None);
                self.state.proposal = Some(p);
                self.state.proposal_block = None;
                return Ok(());
            }
        };

        let proposer_addr = self.proposer_addr_string(&p.proposer);
        if verify_block_with_vset(&self.app_state, &block, &proposer_addr, &p.proposer).is_none() {
            // Block failed execution/verification: prevote NIL.
            self.state.step = Step::Prevote;
            self.step_elapsed_ms = 0;
            self.state.quantum.apply_step_decoherence();
            self.broadcast_vote(signer, out, VoteType::Prevote, None);
            return Ok(());
        }

        let proposal_id = p.block_id.clone();
        self.state.proposal = Some(p);
        self.state.proposal_block = Some(block);

        self.state.step = Step::Prevote;
        self.step_elapsed_ms = 0;
        self.state.quantum.apply_step_decoherence();
        let vote_block = self.prevote_choice(&proposal_id);
        self.broadcast_vote(signer, out, VoteType::Prevote, vote_block);
        Ok(())
    }

    fn prevote_choice(&self, proposal_id: &Hash32) -> Option<Hash32> {
        if let Some(locked) = &self.state.locked_value {
            if locked != proposal_id {
                return None;
            }
        }
        Some(proposal_id.clone())
    }

    fn record_vote_and_detect_evidence(&mut self, v: &Vote) -> Option<Evidence> {
        let key = (v.voter.clone(), v.height, v.round, v.vote_type);
        if let Some((prev_bid, prev_vote)) = self.state.vote_index.get(&key) {
            if prev_bid != &v.block_id {
                self.state.quantum.apply_step_decoherence();
                return Some(Evidence::DoubleVote {
                    voter: v.voter.clone(),
                    height: v.height,
                    round: v.round,
                    vote_type: v.vote_type,
                    a: prev_bid.clone(),
                    b: v.block_id.clone(),
                    vote_a: prev_vote.clone(),
                    vote_b: v.clone(),
                });
            }
        } else {
            self.state
                .vote_index
                .insert(key, (v.block_id.clone(), v.clone()));
        }
        None
    }

    fn on_vote<S: Signer, B: BlockStore, O: Outbox>(
        &mut self,
        signer: &S,
        store: &B,
        out: &mut O,
        v: Vote,
    ) -> Result<(), ConsensusError> {
        if self.state.decided.is_some() {
            return Ok(());
        }
        self.verify_vote(&v)?;

        if let Some(ev) = self.record_vote_and_detect_evidence(&v) {
            self.stakes.apply_evidence(&ev, self.state.height);
            out.broadcast(ConsensusMsg::Evidence(ev));
        }

        // Store the vote (idempotent — same voter/vote_type/round overwrites).
        let rt = self.state.votes.entry(v.round).or_default();
        let vt = rt.entry(v.vote_type).or_default();
        vt.insert(v.voter.clone(), v.clone());

        match v.vote_type {
            VoteType::Prevote => {
                if self.state.step == Step::Prevote {
                    if let Some((bid_opt, pow)) = self.tally(v.round, VoteType::Prevote) {
                        if pow >= quorum_threshold(self.vset.total_power()) {
                            self.state.quantum.apply_quorum_decoherence();
                            self.on_prevote_quorum(signer, store, out, bid_opt);
                        }
                    }
                }
            }
            VoteType::Precommit => {
                if self.state.step == Step::Precommit {
                    if let Some((bid_opt, pow)) = self.tally(v.round, VoteType::Precommit) {
                        if pow >= quorum_threshold(self.vset.total_power()) {
                            self.state.quantum.apply_quorum_decoherence();
                            self.on_precommit_quorum(signer, store, out, bid_opt, v.round)?;
                        }
                    }
                }
            }
        }
        Ok(())
    }

    fn on_prevote_quorum<S: Signer, B: BlockStore, O: Outbox>(
        &mut self,
        signer: &S,
        store: &B,
        out: &mut O,
        bid_opt: Option<Hash32>,
    ) {
        if let Some(bid) = bid_opt {
            self.state.valid_round = Some(self.state.round);
            self.state.valid_value = Some(bid.clone());
            self.state.locked_round = Some(self.state.round);
            self.state.locked_value = Some(bid.clone());
            self.state.step = Step::Precommit;
            self.step_elapsed_ms = 0;
            self.state.quantum.apply_step_decoherence();
            self.broadcast_vote(signer, out, VoteType::Precommit, Some(bid));
        } else {
            // NIL prevote quorum: advance round without locking.
            self.advance_round(signer, store, out);
        }
    }

    fn on_precommit_quorum<S: Signer, B: BlockStore, O: Outbox>(
        &mut self,
        _signer: &S,
        store: &B,
        out: &mut O,
        bid_opt: Option<Hash32>,
        round: Round,
    ) -> Result<(), ConsensusError> {
        let Some(bid) = bid_opt else {
            self.advance_round(_signer, store, out);
            return Ok(());
        };

        let Some(block) = store.get(&bid) else {
            out.request_block(bid.clone());
            return Ok(());
        };

        let proposer_pk = PublicKeyBytes(block.header.proposer_pk.clone());
        let expected_proposer = &self.vset.proposer_for(self.state.height, round).pk;
        let proposer_addr = self.proposer_addr_string(&proposer_pk);

        let Some((new_state, receipts)) = verify_block_with_vset(
            &self.app_state,
            &block,
            &proposer_addr,
            expected_proposer,
        ) else {
            return Err(ConsensusError::Exec);
        };

        let precommits = self.collect_votes(round, VoteType::Precommit, Some(&bid));
        let cert = CommitCertificate {
            height: self.state.height,
            block_id: bid.clone(),
            precommits,
        };
        self.state.decided = Some(cert.clone());
        self.state.step = Step::Commit;
        self.step_elapsed_ms = 0;

        self.app_state = new_state.clone();
        self.prev_block_id = bid.clone();

        let new_base =
            next_base_fee(self.base_fee_per_gas, block.header.gas_used, self.cfg.gas_target);
        self.base_fee_per_gas = new_base;

        self.state.quantum.apply_step_decoherence();
        out.on_commit(&cert, &block, &new_state, new_base, &receipts);
        info!(height = self.state.height, "committed");
        Ok(())
    }

    fn tally(&self, round: Round, vt: VoteType) -> Option<(Option<Hash32>, u64)> {
        let mut tally = VoteTally::default();
        let rt = self.state.votes.get(&round)?;
        let votes = rt.get(&vt)?;
        for (voter, vote) in votes.iter() {
            tally.add_vote(&self.vset, voter, &vote.block_id);
        }
        tally.best()
    }

    fn collect_votes(&self, round: Round, vt: VoteType, target: Option<&Hash32>) -> Vec<Vote> {
        let mut outv = Vec::new();
        let Some(rt) = self.state.votes.get(&round) else {
            return outv;
        };
        let Some(votes) = rt.get(&vt) else {
            return outv;
        };
        for vote in votes.values() {
            let matches = match (target, &vote.block_id) {
                (Some(t), Some(b)) => t == b,
                (None, None) => true,
                _ => false,
            };
            if matches {
                outv.push(vote.clone());
            }
        }
        outv
    }

    /// Check → record → sign → broadcast, in that strict order.
    ///
    /// If `record_vote` fails, no signature is produced and nothing is
    /// broadcast — the caller must treat the failure as fatal for this round.
    fn broadcast_vote<S: Signer, O: Outbox>(
        &self,
        signer: &S,
        out: &mut O,
        vt: VoteType,
        block_id: Option<Hash32>,
    ) {
        // Guard 1: never sign anything if we already decided at this height.
        if self.state.decided.is_some() {
            warn!(
                height = self.state.height,
                "attempted to broadcast vote after decision; ignoring"
            );
            return;
        }

        // Guard 2: check → record BEFORE signing.
        if let Some(g) = &self.ds_guard {
            if let Err(e) = g.check_vote(vt, self.state.height, self.state.round, &block_id) {
                warn!(error = %e, "double-sign guard refused vote signature");
                return;
            }
            if let Err(e) = g.record_vote(vt, self.state.height, self.state.round, &block_id) {
                warn!(error = %e, "double-sign guard write failed — halting vote");
                return;
            }
        }

        let bytes = vote_sign_bytes(vt, self.state.height, self.state.round, &block_id);
        let sig = signer.sign(&bytes);

        let vote = Vote {
            vote_type: vt,
            height: self.state.height,
            round: self.state.round,
            voter: signer.public_key(),
            block_id,
            signature: sig,
        };
        out.broadcast(ConsensusMsg::Vote(vote));
    }

    pub fn on_block_received<S: Signer, B: BlockStore, O: Outbox>(
        &mut self,
        signer: &S,
        store: &B,
        out: &mut O,
        block: Block,
    ) -> Result<(), ConsensusError> {
        store.put(block.clone());
        if let Some(prop) = self.state.proposal.clone() {
            if prop.block_id == block.id() && self.state.proposal_block.is_none() {
                self.state.proposal_block = Some(block);
                if self.state.step == Step::Prevote {
                    let bid = prop.block_id.clone();
                    let vote_block = self.prevote_choice(&bid);
                    self.broadcast_vote(signer, out, VoteType::Prevote, vote_block);
                }
            }
        }
        Ok(())
    }

    /// Advance to the next height.
    ///
    /// Returns `Err(AlreadyDecided)` if the current height has not decided,
    /// which almost always indicates a caller bug.
    pub fn next_height<S: Signer, B: BlockStore, O: Outbox>(
        &mut self,
        signer: &S,
        store: &B,
        out: &mut O,
    ) -> Result<(), ConsensusError> {
        if self.state.decided.is_none() {
            warn!(
                height = self.state.height,
                "next_height called without decision; callers should wait for commit"
            );
            return Err(ConsensusError::AlreadyDecided);
        }
        let next = self.state.height + 1;
        self.state = ConsensusState::new(next);
        self.step_elapsed_ms = 0;
        self.state.step = Step::Propose;
        self.maybe_propose(signer, store, out, |_| vec![]);
        Ok(())
    }
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_config_default_validates() {
        assert!(Config::default().validate().is_ok());
    }

    #[test]
    fn test_config_rejects_zero_timeouts() {
        let c = Config { propose_timeout_ms: 0, ..Default::default() };
        assert!(c.validate().is_err());
        let c = Config { prevote_timeout_ms: 0, ..Default::default() };
        assert!(c.validate().is_err());
        let c = Config { precommit_timeout_ms: 0, ..Default::default() };
        assert!(c.validate().is_err());
    }

    #[test]
    fn test_config_rejects_zero_gas_target() {
        // New check.
        let c = Config { gas_target: 0, ..Default::default() };
        assert!(c.validate().is_err());
        let c = Config { initial_base_fee_per_gas: 0, ..Default::default() };
        assert!(c.validate().is_err());
    }

    #[test]
    fn test_quantum_state_starts_pure() {
        let q = QuantumConsensusState::new();
        assert!((q.purity - 1.0).abs() < 1e-12);
        assert_eq!(q.entropy, 0.0);
        assert!(q.is_healthy);
    }

    #[test]
    fn test_quorum_decoherence_is_gentle() {
        // Regression: the previous implementation used 1/sqrt(4) = 0.5 per
        // quorum, collapsing coherence after four rounds.
        let mut q = QuantumConsensusState::new();
        for _ in 0..100 {
            q.apply_quorum_decoherence();
        }
        // After 100 quorums, purity should still be well above the threshold.
        assert!(
            q.purity > 0.9,
            "purity after 100 quorums = {} (must stay healthy)",
            q.purity
        );
        assert!(q.is_healthy);
    }

    #[test]
    fn test_step_decoherence_decays_gradually() {
        let mut q = QuantumConsensusState::new();
        for _ in 0..1000 {
            q.apply_step_decoherence();
        }
        // 1000 steps × 1e-4 = 10% decay ⇒ purity ≈ 0.90.
        assert!(q.purity < 1.0);
        assert!(q.purity > 0.85);
    }

    #[test]
    fn test_is_decided_accessor() {
        let state = ConsensusState::new(1);
        assert!(state.decided.is_none());
    }
}
