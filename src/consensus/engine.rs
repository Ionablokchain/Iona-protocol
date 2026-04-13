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
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum Step {
    Propose,
    Prevote,
    Precommit,
    Commit,
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct CommitCertificate {
    pub height: Height,
    pub block_id: Hash32,
    pub precommits: Vec<Vote>,
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
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
    /// This is the key to sub-second finality — blocks commit as soon as 2/3+ validators respond.
    pub fast_quorum: bool,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            // Tendermint safety: propose timeout must be long enough for block propagation.
            // At 200ms tick, 300ms gives one full tick + margin before nil-vote fallback.
            propose_timeout_ms: 300,
            // Prevote/precommit timeouts are fallbacks only; fast_quorum bypasses them.
            prevote_timeout_ms: 200,
            precommit_timeout_ms: 200,
            max_rounds: 50,
            // 4096 txs/block @ ~21k gas each = ~86M gas/block (vs ETH's 30M)
            max_txs_per_block: 4096,
            // Gas target = half of max capacity (EIP-1559 design)
            // 43M target vs ETH's 15M → ~3x higher sustained throughput
            gas_target: 43_000_000,
            initial_base_fee_per_gas: 1,
            include_block_in_proposal: true,
            fast_quorum: true,
        }
    }
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
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
        }
    }
}

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

pub struct Engine<V: Verifier> {
    pub cfg: Config,
    pub vset: ValidatorSet,
    pub state: ConsensusState,

    pub prev_block_id: Hash32,
    pub app_state: KvState,

    pub stakes: StakeLedger,
    pub base_fee_per_gas: u64,

    /// Persisted double-sign protection (optional).
    ds_guard: Option<DoubleSignGuard>,

    step_elapsed_ms: u64,
    _v: std::marker::PhantomData<V>,
}

impl<V: Verifier> Engine<V> {
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

    pub fn is_proposer(&self, pk: &PublicKeyBytes) -> bool {
        self.vset
            .proposer_for(self.state.height, self.state.round)
            .pk
            == *pk
    }

    fn proposer_addr_string(&self, pk: &PublicKeyBytes) -> String {
        hex::encode(&blake3::hash(&pk.0).as_bytes()[..20])
    }

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
                // On the first tick of the Propose step (elapsed was 0 before adding dt),
                // attempt to build a proposal if we are the designated proposer.
                // The condition `self.step_elapsed_ms == dt_ms` means we just entered this step.
                let first_tick = self.step_elapsed_ms == dt_ms;
                if first_tick && self.state.proposal.is_none() {
                    self.maybe_propose(signer, store, out, mempool_drain);
                }
                // Fast-path: if we already have a valid proposal block, prevote immediately
                // without waiting for propose_timeout_ms. This is the key to sub-second blocks:
                // once block is received and validated, we don't need to wait.
                let has_valid_proposal = self.cfg.fast_quorum
                    && self.state.proposal.is_some()
                    && self.state.proposal_block.is_some();
                if has_valid_proposal || self.step_elapsed_ms >= self.cfg.propose_timeout_ms {
                    self.state.step = Step::Prevote;
                    self.step_elapsed_ms = 0;
                    let vote_block = self.state.proposal.as_ref().and_then(|p| {
                        if self.state.proposal_block.is_some() {
                            Some(p.block_id.clone())
                        } else {
                            None
                        }
                    });
                    self.broadcast_vote(signer, out, VoteType::Prevote, vote_block);
                }
            }
            Step::Prevote => {
                if self.step_elapsed_ms >= self.cfg.prevote_timeout_ms {
                    self.advance_round(signer, store, out);
                }
            }
            Step::Precommit => {
                if self.step_elapsed_ms >= self.cfg.precommit_timeout_ms {
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
        if self.state.round + 1 >= self.cfg.max_rounds {
            warn!(
                height = self.state.height,
                round = self.state.round,
                "max rounds reached; staying"
            );
            return;
        }
        self.state.round += 1;
        self.state.proposal = None;
        self.state.proposal_block = None;
        self.state.step = Step::Propose;
        self.step_elapsed_ms = 0;
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
        // If a proposal is already present (e.g. produced by an external proposer loop),
        // do not create a second proposal for the same height/round.
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
        store.put(block.clone());

        if let Some(g) = &self.ds_guard {
            if let Err(e) = g.check_proposal(self.state.height, self.state.round, &bid) {
                warn!("double-sign guard refused proposal signature: {e}");
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
        if let Some(g) = &self.ds_guard {
            if let Err(e) = g.record_proposal(self.state.height, self.state.round, &bid) {
                warn!("double-sign guard write failed — halting proposal: {e}");
                return;
            }
        }

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

        out.broadcast(ConsensusMsg::Proposal(prop));
        info!(
            height = self.state.height,
            round = self.state.round,
            "broadcast proposal"
        );
    }

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
                // Apply evidence using the current consensus height.
                self.stakes.apply_evidence(&ev, self.state.height);
                Ok(())
            }
        }
    }

    fn verify_proposal(&self, p: &Proposal) -> Result<(), ConsensusError> {
        if !self.vset.contains(&p.proposer) {
            return Err(ConsensusError::UnknownValidator);
        }
        // Must be the designated proposer for this height+round (round-robin)
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
        mut p: Proposal,
    ) -> Result<(), ConsensusError> {
        if self.state.decided.is_some() {
            return Ok(());
        }
        self.verify_proposal(&p)?;

        if let Some(b) = p.block.clone() {
            store.put(b);
        }

        let block = store.get(&p.block_id);
        if block.is_none() {
            out.request_block(p.block_id.clone());
            self.state.step = Step::Prevote;
            self.step_elapsed_ms = 0;
            self.broadcast_vote(signer, out, VoteType::Prevote, None);
            self.state.proposal = Some(p);
            self.state.proposal_block = None;
            return Ok(());
        }

        let Some(block) = block else {
            return Ok(());
        };
        let proposer_addr = self.proposer_addr_string(&p.proposer);
        if verify_block_with_vset(&self.app_state, &block, &proposer_addr, &p.proposer).is_none() {
            self.state.step = Step::Prevote;
            self.step_elapsed_ms = 0;
            self.broadcast_vote(signer, out, VoteType::Prevote, None);
            return Ok(());
        }

        let proposal_id = p.block_id.clone();
        self.state.proposal = Some(p);
        self.state.proposal_block = Some(block);

        self.state.step = Step::Prevote;
        self.step_elapsed_ms = 0;
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

        let rt = self.state.votes.entry(v.round).or_default();
        let vt = rt.entry(v.vote_type).or_default();
        vt.insert(v.voter.clone(), v.clone());

        match v.vote_type {
            VoteType::Prevote => {
                if self.state.step == Step::Prevote {
                    if let Some((bid_opt, pow)) = self.tally(v.round, VoteType::Prevote) {
                        let q = quorum_threshold(self.vset.total_power());
                        if pow >= q {
                            if let Some(bid) = bid_opt {
                                self.state.valid_round = Some(self.state.round);
                                self.state.valid_value = Some(bid.clone());
                                self.state.locked_round = Some(self.state.round);
                                self.state.locked_value = Some(bid.clone());
                                self.state.step = Step::Precommit;
                                self.step_elapsed_ms = 0;
                                self.broadcast_vote(signer, out, VoteType::Precommit, Some(bid));
                            } else {
                                self.advance_round(signer, store, out);
                            }
                        }
                    }
                }
            }
            VoteType::Precommit => {
                if self.state.step == Step::Precommit {
                    if let Some((bid_opt, pow)) = self.tally(v.round, VoteType::Precommit) {
                        let q = quorum_threshold(self.vset.total_power());
                        if pow >= q {
                            if let Some(bid) = bid_opt {
                                let block = store.get(&bid);
                                if block.is_none() {
                                    out.request_block(bid.clone());
                                    return Ok(());
                                }
                                let Some(block) = block else {
                                    return Ok(());
                                };
                                let proposer_pk = PublicKeyBytes(block.header.proposer_pk.clone());
                                let expected_proposer =
                                    &self.vset.proposer_for(self.state.height, v.round).pk;
                                let proposer_addr = self.proposer_addr_string(&proposer_pk);
                                let (new_state, _receipts) = verify_block_with_vset(
                                    &self.app_state,
                                    &block,
                                    &proposer_addr,
                                    expected_proposer,
                                )
                                .ok_or(ConsensusError::Exec)?;

                                let precommits =
                                    self.collect_votes(v.round, VoteType::Precommit, Some(&bid));
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

                                let new_base = next_base_fee(
                                    self.base_fee_per_gas,
                                    block.header.gas_used,
                                    self.cfg.gas_target,
                                );
                                self.base_fee_per_gas = new_base;

                                out.on_commit(&cert, &block, &new_state, new_base, &_receipts);
                                info!(height = self.state.height, "committed");
                            } else {
                                self.advance_round(signer, store, out);
                            }
                        }
                    }
                }
            }
        }
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
        for (_voter, vote) in votes.iter() {
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

    fn broadcast_vote<S: Signer, O: Outbox>(
        &self,
        signer: &S,
        out: &mut O,
        vt: VoteType,
        block_id: Option<Hash32>,
    ) {
        if let Some(g) = &self.ds_guard {
            if let Err(e) = g.check_vote(vt, self.state.height, self.state.round, &block_id) {
                warn!("double-sign guard refused vote signature: {e}");
                return;
            }
        }

        let bytes = vote_sign_bytes(vt, self.state.height, self.state.round, &block_id);
        let sig = signer.sign(&bytes);
        if let Some(g) = &self.ds_guard {
            if let Err(e) = g.record_vote(vt, self.state.height, self.state.round, &block_id) {
                warn!("double-sign guard write failed — halting vote: {e}");
                return;
            }
        }
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

    /// Handle a block received from sync (range response).
    pub fn on_block_received<S: Signer, B: BlockStore, O: Outbox>(
        &mut self,
        signer: &S,
        store: &B,
        out: &mut O,
        block: Block,
    ) -> Result<(), ConsensusError> {
        store.put(block.clone());
        // If we had a pending proposal referencing this block, retry it
        if let Some(prop) = self.state.proposal.clone() {
            if prop.block_id == block.id() && self.state.proposal_block.is_none() {
                self.state.proposal_block = Some(block);
                // Now we can prevote
                if self.state.step == Step::Prevote {
                    let bid = prop.block_id.clone();
                    let vote_block = self.prevote_choice(&bid);
                    self.broadcast_vote(signer, out, VoteType::Prevote, vote_block);
                }
            }
        }
        Ok(())
    }

    pub fn next_height<S: Signer, B: BlockStore, O: Outbox>(
        &mut self,
        signer: &S,
        store: &B,
        out: &mut O,
    ) {
        self.state = ConsensusState::new(self.state.height + 1);
        self.step_elapsed_ms = 0;
        self.state.step = Step::Propose;
        self.maybe_propose(signer, store, out, |_| vec![]);
    }
}
