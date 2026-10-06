//! IONA consensus engine and supporting modules — Production-Grade.
//!
//! # Model
//!
//! This module wires together a Tendermint-style BFT consensus engine with
//! double-sign protection, adaptive finality, diagnostics, block production,
//! and (informational) decoherence scorekeeping.
//!
//! The consensus engine itself is a **classical** BFT state machine. The
//! "quantum" fields (`purity`, `entropy`, `coherence`) are decorative
//! scoreboards exposed for observability. They **never** gate a decision and
//! **never** cause an error. See [`QuantumConsensusState`] for details.
//!
//! # Module Overview
//!
//! | Module | Purpose |
//! |--------|---------|
//! | `engine` | BFT state machine |
//! | `messages` | Proposal / Vote types + sign bytes |
//! | `double_sign` | Equivocation protection |
//! | `fast_finality` | Sub-second commit + adaptive timeouts |
//! | `quorum` | Vote counting |
//! | `diagnostic` | Stall detection |
//! | `validator_set` | Validator management |
//! | `block_producer` | Block creation |
//! | `debug_trace` | Event tracing |
//! | `genesis` | Chain initialisation |
//!
//! # Concurrency
//!
//! [`ConsensusManager`] is `Clone + Send + Sync`. All internal state is
//! behind [`parking_lot::Mutex`], which does not poison on panic. Clones
//! share state via `Arc`.

pub mod block_producer;
pub mod debug_trace;
pub mod diagnostic;
pub mod double_sign;
pub mod engine;
pub mod fast_finality;
pub mod genesis;
pub mod messages;
pub mod quorum;
pub mod quorum_diag;
pub mod validator_set;

// ── Re-exports ────────────────────────────────────────────────────────────

pub use block_producer::*;
pub use debug_trace::*;
pub use diagnostic::*;
pub use double_sign::*;
pub use engine::*;
pub use fast_finality::*;
pub use genesis::*;
pub use messages::*;
pub use quorum::*;
pub use quorum_diag::*;
pub use validator_set::*;

// ── External dependencies ────────────────────────────────────────────────

use crate::crypto::{PublicKeyBytes, Signer, Verifier};
use crate::execution::KvState;
use crate::slashing::StakeLedger;
use crate::types::{Hash32, Height};
use parking_lot::Mutex;
use prometheus::{CounterVec, Gauge};
use serde::{Deserialize, Serialize};
use std::sync::Arc;

// ── Constants ────────────────────────────────────────────────────────────

/// Default decoherence rate per consensus step.
pub const STEP_DECOHERENCE_RATE: f64 = 0.0001;

/// Decoherence rate per timeout (stronger than a step).
pub const TIMEOUT_DECOHERENCE_RATE: f64 = 0.0005;

/// Decoherence applied on each successful quorum.
///
/// **Note**: this is a small, per-quorum value. A previous version derived
/// this from a "Kraus rank" of 4 (`1/sqrt(4) = 0.5`), which collapsed
/// coherence to ~0 after four quorums and locked `is_healthy` at `false`
/// for the rest of the node's life.
pub const QUORUM_DECOHERENCE_RATE: f64 = 0.001;

/// Coherence threshold below which `is_healthy` flips to `false`.
///
/// This is **informational only** — it never gates a decision.
pub const MIN_CONSENSUS_COHERENCE: f64 = 0.9;

/// Numerator of the BFT quorum threshold (2/3).
pub const QUORUM_NUMERATOR: u64 = 2;

/// Denominator of the BFT quorum threshold (2/3).
pub const QUORUM_DENOMINATOR: u64 = 3;

// ── Quantum Consensus State ─────────────────────────────────────────────

/// Decoherence scoreboard for consensus operations.
///
/// **This never gates a decision.** It exists so operators can observe
/// long-running decoherence trends correlated with network events. Purity
/// and entropy decay with activity and are reset only by constructing a
/// fresh instance.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct QuantumConsensusState {
    /// Purity γ = Tr(ρ²), in `[0, 1]`.
    pub purity: f64,
    /// Informational entropy proxy, ≥ 0.
    pub entropy: f64,
    /// Coherence of the current step, in `[0, 1]`.
    pub step_coherence: f64,
    /// Entanglement fidelity with the validator set, in `[0, 1]`.
    pub validator_entanglement: f64,
    /// Total step transitions performed.
    pub total_transitions: u64,
    /// Total quorum measurements performed.
    pub total_quorums: u64,
    /// Total timeouts experienced.
    pub total_timeouts: u64,
    /// Whether coherence is at or above [`MIN_CONSENSUS_COHERENCE`].
    /// Informational only.
    pub is_healthy: bool,
}

impl Default for QuantumConsensusState {
    fn default() -> Self {
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
}

impl QuantumConsensusState {
    /// Fresh state, fully coherent.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Apply decoherence from a step transition.
    pub fn apply_step_decoherence(&mut self) {
        self.total_transitions = self.total_transitions.saturating_add(1);
        let decay = (-STEP_DECOHERENCE_RATE).exp();
        self.step_coherence = (self.step_coherence * decay).clamp(0.0, 1.0);
        self.validator_entanglement =
            (self.validator_entanglement * decay.sqrt()).clamp(0.0, 1.0);
        self.recompute();
    }

    /// Apply decoherence from a timeout.
    pub fn apply_timeout_decoherence(&mut self) {
        self.total_timeouts = self.total_timeouts.saturating_add(1);
        let decay = (-TIMEOUT_DECOHERENCE_RATE).exp();
        self.step_coherence = (self.step_coherence * decay).clamp(0.0, 1.0);
        self.recompute();
    }

    /// Apply decoherence from a successful quorum.
    ///
    /// Uses [`QUORUM_DECOHERENCE_RATE`] — intentionally small so a
    /// long-running healthy node accumulates only a slow drift, not a
    /// collapse.
    pub fn apply_quorum_decoherence(&mut self) {
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
            -(self.purity * self.purity.ln().min(0.0))
        };
        self.is_healthy = self.purity >= MIN_CONSENSUS_COHERENCE;
    }
}

// ── Unified Configuration ────────────────────────────────────────────────

/// Configuration for the entire consensus subsystem.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ConsensusConfig {
    pub engine: engine::Config,
    pub double_sign: double_sign::GuardConfig,
    pub fast_finality: fast_finality::FinalityConfig,
    pub diagnostic: diagnostic::DiagnosticConfig,
    pub block_producer: block_producer::ProducerConfig,
    pub enable_metrics: bool,
    pub enable_quantum_tracking: bool,
}

impl Default for ConsensusConfig {
    fn default() -> Self {
        Self {
            engine: engine::Config::default(),
            double_sign: double_sign::GuardConfig::default(),
            fast_finality: fast_finality::FinalityConfig::default(),
            diagnostic: diagnostic::DiagnosticConfig::default(),
            block_producer: block_producer::ProducerConfig::default(),
            enable_metrics: true,
            enable_quantum_tracking: true,
        }
    }
}

impl ConsensusConfig {
    /// Validate every sub-config.
    pub fn validate(&self) -> Result<(), String> {
        self.engine.validate()?;
        self.double_sign.validate()?;
        self.fast_finality.validate()?;
        self.diagnostic.validate()?;
        self.block_producer.validate()?;
        Ok(())
    }
}

// ── Metrics ──────────────────────────────────────────────────────────────

/// Prometheus metrics for the consensus subsystem.
///
/// # Registration
///
/// [`ConsensusMetrics::new`] registers with the **default** Prometheus
/// registry and can only be called once per process. [`ConsensusMetrics::default`]
/// returns an **unregistered** instance safe to construct any number of times.
#[derive(Clone)]
pub struct ConsensusMetrics {
    pub height: Gauge,
    pub round: Gauge,
    pub step: Gauge,
    pub proposals: CounterVec,
    pub prevotes: CounterVec,
    pub precommits: CounterVec,
    pub commits: CounterVec,
    pub timeouts: CounterVec,
    pub double_signs: CounterVec,
    pub finality_lag: Gauge,
    pub quantum_purity: Gauge,
    pub quantum_entropy: Gauge,
}

impl ConsensusMetrics {
    /// Register all metrics with the default Prometheus registry.
    ///
    /// Returns `Err` on name collision (including a second call in the same
    /// process).
    pub fn new() -> Result<Self, prometheus::Error> {
        let height = prometheus::register_gauge!(
            "iona_consensus_height",
            "Current block height"
        )?;
        let round = prometheus::register_gauge!(
            "iona_consensus_round",
            "Current consensus round"
        )?;
        let step = prometheus::register_gauge!(
            "iona_consensus_step",
            "Current step (0=Propose,1=Prevote,2=Precommit,3=Commit)"
        )?;
        let proposals = prometheus::register_counter_vec!(
            "iona_consensus_proposals_total",
            "Proposal messages",
            &["type"]
        )?;
        let prevotes = prometheus::register_counter_vec!(
            "iona_consensus_prevotes_total",
            "Prevote messages",
            &["type"]
        )?;
        let precommits = prometheus::register_counter_vec!(
            "iona_consensus_precommits_total",
            "Precommit messages",
            &["type"]
        )?;
        let commits = prometheus::register_counter_vec!(
            "iona_consensus_commits_total",
            "Commit events",
            &["type"]
        )?;
        let timeouts = prometheus::register_counter_vec!(
            "iona_consensus_timeouts_total",
            "Timeout events",
            &["type"]
        )?;
        let double_signs = prometheus::register_counter_vec!(
            "iona_consensus_double_signs_total",
            "Double-sign detections",
            &["type"]
        )?;
        let finality_lag = prometheus::register_gauge!(
            "iona_consensus_finality_lag_blocks",
            "Finality lag in blocks"
        )?;
        let quantum_purity = prometheus::register_gauge!(
            "iona_consensus_quantum_purity",
            "Informational purity of consensus state"
        )?;
        let quantum_entropy = prometheus::register_gauge!(
            "iona_consensus_quantum_entropy",
            "Informational entropy of consensus state"
        )?;

        Ok(Self {
            height,
            round,
            step,
            proposals,
            prevotes,
            precommits,
            commits,
            timeouts,
            double_signs,
            finality_lag,
            quantum_purity,
            quantum_entropy,
        })
    }

    /// Create an **unregistered** metrics bundle.
    ///
    /// Never fails, never registers. Suitable for tests and for callers
    /// using a custom Prometheus registry.
    pub fn unregistered() -> Self {
        let mk_gauge = |name: &str, help: &str| {
            Gauge::new(name, help).expect("gauge construction is infallible for these names")
        };
        let mk_counter = |name: &str, help: &str| {
            CounterVec::new(prometheus::Opts::new(name, help), &["type"])
                .expect("counter construction is infallible for these names")
        };

        Self {
            height: mk_gauge("iona_consensus_height", "Current block height"),
            round: mk_gauge("iona_consensus_round", "Current consensus round"),
            step: mk_gauge(
                "iona_consensus_step",
                "Current step (0=Propose,1=Prevote,2=Precommit,3=Commit)",
            ),
            proposals: mk_counter("iona_consensus_proposals_total", "Proposal messages"),
            prevotes: mk_counter("iona_consensus_prevotes_total", "Prevote messages"),
            precommits: mk_counter("iona_consensus_precommits_total", "Precommit messages"),
            commits: mk_counter("iona_consensus_commits_total", "Commit events"),
            timeouts: mk_counter("iona_consensus_timeouts_total", "Timeout events"),
            double_signs: mk_counter(
                "iona_consensus_double_signs_total",
                "Double-sign detections",
            ),
            finality_lag: mk_gauge(
                "iona_consensus_finality_lag_blocks",
                "Finality lag in blocks",
            ),
            quantum_purity: mk_gauge(
                "iona_consensus_quantum_purity",
                "Informational purity of consensus state",
            ),
            quantum_entropy: mk_gauge(
                "iona_consensus_quantum_entropy",
                "Informational entropy of consensus state",
            ),
        }
    }

    pub fn set_height(&self, h: u64) {
        self.height.set(h as f64);
    }
    pub fn set_round(&self, r: u32) {
        self.round.set(r as f64);
    }
    pub fn set_step(&self, step: u8) {
        self.step.set(step as f64);
    }
    pub fn record_proposal(&self, typ: &str) {
        self.proposals.with_label_values(&[typ]).inc();
    }
    pub fn record_prevote(&self, typ: &str) {
        self.prevotes.with_label_values(&[typ]).inc();
    }
    pub fn record_precommit(&self, typ: &str) {
        self.precommits.with_label_values(&[typ]).inc();
    }
    pub fn record_commit(&self, typ: &str) {
        self.commits.with_label_values(&[typ]).inc();
    }
    pub fn record_timeout(&self, typ: &str) {
        self.timeouts.with_label_values(&[typ]).inc();
    }
    pub fn record_double_sign(&self, typ: &str) {
        self.double_signs.with_label_values(&[typ]).inc();
    }
    pub fn set_finality_lag(&self, lag: u64) {
        self.finality_lag.set(lag as f64);
    }
    pub fn set_quantum_purity(&self, purity: f64) {
        self.quantum_purity.set(purity);
    }
    pub fn set_quantum_entropy(&self, entropy: f64) {
        self.quantum_entropy.set(entropy);
    }
}

impl Default for ConsensusMetrics {
    fn default() -> Self {
        Self::unregistered()
    }
}

// ── ConsensusManager ─────────────────────────────────────────────────────

/// Thread-safe manager for the consensus subsystem.
///
/// Holds the engine, validator set, double-sign guard, fast finality
/// tracker, informational quantum scoreboard, and metrics.
///
/// # Cloning
///
/// Cloning shares state via `Arc`. Clones observe each other's writes.
#[derive(Clone)]
pub struct ConsensusManager {
    config: Arc<ConsensusConfig>,
    metrics: Arc<ConsensusMetrics>,
    quantum_state: Arc<Mutex<QuantumConsensusState>>,
    engine: Arc<Mutex<engine::Engine<dyn Verifier>>>,
    double_sign: Arc<DoubleSignGuard>,
    fast_finality: Arc<Mutex<fast_finality::FinalityTracker>>,
    validator_set: Arc<Mutex<ValidatorSet>>,
    stake_ledger: Arc<Mutex<StakeLedger>>,
}

impl ConsensusManager {
    /// Create a new consensus manager.
    ///
    /// # Errors
    ///
    /// - Config validation fails.
    /// - Double-sign guard cannot be loaded (integrity failure is fatal).
    ///
    /// # Object safety
    ///
    /// `dyn Verifier` requires [`Verifier`] to be object-safe.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        config: ConsensusConfig,
        validator_set: ValidatorSet,
        height: Height,
        prev_block_id: Hash32,
        app_state: KvState,
        stake_ledger: StakeLedger,
        signer: &dyn Signer,
    ) -> Result<Self, String> {
        config.validate()?;

        let metrics = if config.enable_metrics {
            ConsensusMetrics::new().unwrap_or_else(|e| {
                tracing::warn!(
                    error = %e,
                    "consensus metrics already registered; using unregistered instance"
                );
                ConsensusMetrics::unregistered()
            })
        } else {
            ConsensusMetrics::unregistered()
        };

        let config = Arc::new(config);
        let metrics = Arc::new(metrics);
        let quantum_state = Arc::new(Mutex::new(QuantumConsensusState::new()));

        let guard = DoubleSignGuard::with_config(
            "./data",
            &signer.public_key(),
            &config.double_sign,
        )
        .map_err(|e| format!("failed to create double-sign guard: {}", e))?;

        let engine = engine::Engine::new(
            config.engine.clone(),
            validator_set.clone(),
            height,
            prev_block_id,
            app_state,
            stake_ledger.clone(),
            Some(guard.clone()),
        );

        let finality =
            fast_finality::FinalityTracker::with_config(height, &config.fast_finality);

        Ok(Self {
            config,
            metrics,
            quantum_state,
            engine: Arc::new(Mutex::new(engine)),
            double_sign: Arc::new(guard),
            fast_finality: Arc::new(Mutex::new(finality)),
            validator_set: Arc::new(Mutex::new(validator_set)),
            stake_ledger: Arc::new(Mutex::new(stake_ledger)),
        })
    }

    /// Access the engine mutex.
    ///
    /// **Do not** hold the returned lock across another `ConsensusManager`
    /// method call — `parking_lot::Mutex` is not reentrant.
    pub fn engine(&self) -> &Mutex<engine::Engine<dyn Verifier>> {
        &self.engine
    }

    /// Snapshot of the current validator set.
    pub fn validator_set(&self) -> ValidatorSet {
        self.validator_set.lock().clone()
    }

    /// Replace the validator set in both the manager and the engine.
    ///
    /// The `Engine` field is named `vset` (not `validator_set`).
    pub fn update_validator_set(&self, vset: ValidatorSet) {
        *self.validator_set.lock() = vset.clone();
        self.engine.lock().vset = vset;
    }

    /// Snapshot of the current stake ledger.
    pub fn stake_ledger(&self) -> StakeLedger {
        self.stake_ledger.lock().clone()
    }

    /// Record a commit event and update metrics + scoreboards.
    ///
    /// Reads purity/entropy under a single lock and drops both locks before
    /// touching metrics (avoids holding multiple locks at once).
    pub fn record_commit(&self, height: Height, round: u32, finality_ms: u64) {
        let (finality_purity, finality_entropy) = {
            let mut f = self.fast_finality.lock();
            f.record_commit(finality_ms, round, &self.config.fast_finality);
            (f.purity, f.entropy)
        };

        let (q_purity, q_entropy) = {
            let mut q = self.quantum_state.lock();
            q.apply_quorum_decoherence();
            (q.purity, q.entropy)
        };

        self.metrics.record_commit("ok");
        self.metrics.set_height(height);
        self.metrics.set_round(round);
        self.metrics.set_step(step_to_u8(engine::Step::Commit));
        self.metrics.set_finality_lag(0);
        // The quantum metric is the *composite* of the two scoreboards.
        self.metrics
            .set_quantum_purity(q_purity.min(finality_purity));
        self.metrics
            .set_quantum_entropy(q_entropy.max(finality_entropy));
    }

    /// Record a timeout event.
    pub fn record_timeout(&self) {
        let (purity, entropy) = {
            let mut q = self.quantum_state.lock();
            q.apply_timeout_decoherence();
            (q.purity, q.entropy)
        };
        self.metrics.record_timeout("step");
        self.metrics.set_quantum_purity(purity);
        self.metrics.set_quantum_entropy(entropy);
    }

    /// Record a step transition.
    pub fn record_step_transition(&self) {
        let (purity, entropy) = {
            let mut q = self.quantum_state.lock();
            q.apply_step_decoherence();
            (q.purity, q.entropy)
        };
        self.metrics.set_quantum_purity(purity);
        self.metrics.set_quantum_entropy(entropy);
    }

    /// Snapshot of the informational quantum scoreboard.
    pub fn quantum_state(&self) -> QuantumConsensusState {
        self.quantum_state.lock().clone()
    }

    /// Snapshot of the current metrics.
    ///
    /// Locks the engine **once** (not three times) so the height/round/step
    /// are internally consistent.
    pub fn metrics_snapshot(&self) -> ConsensusMetricsSnapshot {
        let (height, round, step) = {
            let e = self.engine.lock();
            (
                e.state.height,
                e.state.round,
                step_to_u8(e.state.step),
            )
        };
        let (finality_purity, finality_entropy) = {
            let f = self.fast_finality.lock();
            (f.purity, f.entropy)
        };
        let (quantum_purity, quantum_entropy, is_quantum_healthy) = {
            let q = self.quantum_state.lock();
            (q.purity, q.entropy, q.is_healthy)
        };

        ConsensusMetricsSnapshot {
            height,
            round,
            step,
            finality_purity,
            finality_entropy,
            quantum_purity,
            quantum_entropy,
            is_quantum_healthy,
            double_sign_detections: self.double_sign.detections(),
        }
    }

    /// Produce a diagnostic snapshot.
    ///
    /// Uses the stake-weighted `diagnose_with_stake` path with the manager's
    /// `stake_ledger`, and passes the real `propose_timeout_ms` (not `0`).
    pub fn diagnose(
        &self,
        connected_validators: &[PublicKeyBytes],
        step_elapsed_ms: u64,
    ) -> diagnostic::ConsensusDiagnostic {
        let state = self.engine.lock().state.clone();
        let vset = self.validator_set.lock().clone();
        let ledger = self.stake_ledger.lock().clone();

        diagnostic::diagnose_with_stake(
            &state,
            &vset,
            &ledger,
            connected_validators,
            step_elapsed_ms,
            self.config.engine.propose_timeout_ms,
            &self.config.diagnostic,
        )
    }

    /// Configuration.
    pub fn config(&self) -> &ConsensusConfig {
        &self.config
    }

    /// The underlying double-sign guard.
    pub fn double_sign_guard(&self) -> &DoubleSignGuard {
        &self.double_sign
    }
}

/// Map a [`engine::Step`] to its stable numeric index for metrics.
#[inline]
fn step_to_u8(step: engine::Step) -> u8 {
    match step {
        engine::Step::Propose => 0,
        engine::Step::Prevote => 1,
        engine::Step::Precommit => 2,
        engine::Step::Commit => 3,
    }
}

/// Snapshot of consensus metrics.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ConsensusMetricsSnapshot {
    pub height: u64,
    pub round: u32,
    pub step: u8,
    pub finality_purity: f64,
    pub finality_entropy: f64,
    pub quantum_purity: f64,
    pub quantum_entropy: f64,
    pub is_quantum_healthy: bool,
    pub double_sign_detections: u64,
}

// ── Utility functions ────────────────────────────────────────────────────

/// Compute the BFT quorum threshold (`floor(total × 2 / 3) + 1`).
///
/// `total == 0` returns `1` (defensive; an empty set cannot reach quorum).
#[must_use]
pub fn quorum_threshold(total_power: u64) -> u64 {
    if total_power == 0 {
        return 1;
    }
    (total_power * QUORUM_NUMERATOR / QUORUM_DENOMINATOR) + 1
}

/// Whether `voting_power` meets the quorum threshold for `total_power`.
#[must_use]
pub fn has_quorum(voting_power: u64, total_power: u64) -> bool {
    voting_power >= quorum_threshold(total_power)
}

/// Average of the given coherences, clamped to `[0, 1]`.
///
/// Returns `1.0` for an empty input (vacuously pure). NaN inputs map to `0.0`.
#[must_use]
pub fn compute_consensus_purity(coherences: &[f64]) -> f64 {
    if coherences.is_empty() {
        return 1.0;
    }
    let avg = coherences.iter().sum::<f64>() / coherences.len() as f64;
    if avg.is_nan() {
        0.0
    } else {
        avg.clamp(0.0, 1.0)
    }
}

/// **Binary Shannon entropy** of `purity` interpreted as a probability.
///
/// ```text
/// S(p) = -p ln p - (1 - p) ln (1 - p)
/// ```
///
/// This is **not** the von Neumann entropy of a density matrix. It is a
/// convenient proxy that is `0` at `p ∈ {0, 1}` and maximal at `p = 0.5`.
/// Non-finite or out-of-range `purity` returns `0.0`.
#[must_use]
pub fn compute_consensus_entropy(purity: f64) -> f64 {
    if !purity.is_finite() || purity <= 0.0 || purity >= 1.0 {
        return 0.0;
    }
    -purity * purity.ln() - (1.0 - purity) * (1.0 - purity).ln()
}

// ── Prelude ──────────────────────────────────────────────────────────────

/// Curated imports for downstream crates.
pub mod prelude {
    pub use super::block_producer::{ProducerConfig, SimpleBlockProducer};
    pub use super::debug_trace::{
        ConsensusEvent, ConsensusTracer, StateRootLog, StateRootLogEntry,
    };
    pub use super::diagnostic::{
        diagnose, diagnose_with_stake, ConsensusDiagnostic, DiagnosticConfig,
        DiagnosticStats, StallReason,
    };
    pub use super::double_sign::{vote_guard_key, DoubleSignGuard, GuardStats};
    pub use super::engine::{
        BlockStore, CommitCertificate, Config, ConsensusState, Engine, Outbox, Step,
    };
    pub use super::fast_finality::{
        FinalityCertificate, FinalityStats, FinalityTracker, PipelineState,
    };
    pub use super::messages::{
        proposal_sign_bytes, sign_bytes_fidelity, vote_sign_bytes, ConsensusMsg,
        MessageStats, Proposal, Vote, VoteType,
    };
    pub use super::quorum::{quorum_threshold, QuorumCalculator, VoteTally};
    pub use super::quorum_diag::QuorumDiagnostic;
    pub use super::validator_set::{Validator, ValidatorSet};
    pub use super::{
        compute_consensus_entropy, compute_consensus_purity, has_quorum,
        quorum_threshold, ConsensusConfig, ConsensusManager, ConsensusMetrics,
        ConsensusMetricsSnapshot, QuantumConsensusState, MIN_CONSENSUS_COHERENCE,
        QUORUM_DECOHERENCE_RATE, QUORUM_DENOMINATOR, QUORUM_NUMERATOR,
        STEP_DECOHERENCE_RATE, TIMEOUT_DECOHERENCE_RATE,
    };
}

// ── Tests ─────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::ed25519::Ed25519Keypair;

    fn test_signer() -> Ed25519Keypair {
        Ed25519Keypair::from_seed([0u8; 32])
    }

    // ── Quantum state ───────────────────────────────────────────────────

    #[test]
    fn test_quantum_state_initialization() {
        let state = QuantumConsensusState::new();
        assert!((state.purity - 1.0).abs() < 1e-10);
        assert!((state.entropy - 0.0).abs() < 1e-10);
        assert!(state.is_healthy);
    }

    #[test]
    fn test_step_decoherence() {
        let mut state = QuantumConsensusState::new();
        let initial = state.purity;
        state.apply_step_decoherence();
        assert!(state.purity < initial);
        assert_eq!(state.total_transitions, 1);
    }

    #[test]
    fn test_timeout_decoherence_stronger_than_step() {
        let mut after_step = QuantumConsensusState::new();
        after_step.apply_step_decoherence();

        let mut after_timeout = QuantumConsensusState::new();
        after_timeout.apply_timeout_decoherence();

        assert!(after_timeout.purity < after_step.purity);
        assert_eq!(after_timeout.total_timeouts, 1);
    }

    #[test]
    fn test_quorum_decoherence_is_gentle() {
        // Regression: the previous implementation used a Kraus factor of
        // 1/sqrt(4) = 0.5 per quorum, collapsing coherence to ~0 after four
        // quorums and permanently flipping `is_healthy` to false.
        let mut state = QuantumConsensusState::new();
        for _ in 0..100 {
            state.apply_quorum_decoherence();
        }
        assert!(
            state.purity > MIN_CONSENSUS_COHERENCE,
            "purity after 100 quorums = {} (must stay healthy)",
            state.purity
        );
        assert!(state.is_healthy);
    }

    #[test]
    fn test_purity_never_negative() {
        let mut state = QuantumConsensusState::new();
        for _ in 0..10_000 {
            state.apply_timeout_decoherence();
        }
        assert!(state.purity >= 0.0);
        assert!(state.purity.is_finite());
    }

    #[test]
    fn test_health_flips_after_sustained_decoherence() {
        let mut state = QuantumConsensusState::new();
        assert!(state.is_healthy);
        for _ in 0..10_000 {
            state.apply_step_decoherence();
        }
        assert!(!state.is_healthy);
    }

    // ── Config ──────────────────────────────────────────────────────────

    #[test]
    fn test_config_default() {
        assert!(ConsensusConfig::default().validate().is_ok());
    }

    // ── Metrics ─────────────────────────────────────────────────────────

    #[test]
    fn test_metrics_unregistered_is_repeatable() {
        // Regression: `Default` used to call `new()` with a chain of
        // `.unwrap()`, panicking on the second instantiation.
        let _a = ConsensusMetrics::unregistered();
        let _b = ConsensusMetrics::unregistered();
        let _c = ConsensusMetrics::default();
    }

    #[test]
    fn test_metrics_records() {
        let m = ConsensusMetrics::unregistered();
        m.set_height(10);
        m.set_round(2);
        m.set_step(1);
        m.record_proposal("sent");
        m.record_commit("ok");
        m.set_finality_lag(3);
        m.set_quantum_purity(0.95);
        m.set_quantum_entropy(0.05);
    }

    // ── Manager ─────────────────────────────────────────────────────────

    #[test]
    fn test_manager_creation() {
        let signer = test_signer();
        let manager = ConsensusManager::new(
            ConsensusConfig::default(),
            ValidatorSet::default(),
            1,
            Hash32::zero(),
            KvState::default(),
            StakeLedger::default(),
            &signer,
        )
        .expect("manager creation should succeed");
        assert_eq!(manager.double_sign_guard().detections(), 0);
        assert!(manager.quantum_state().is_healthy);
    }

    #[test]
    fn test_manager_update_validator_set() {
        // Regression: previously wrote to `engine.validator_set`, which
        // does not exist (`Engine` names the field `vset`).
        let signer = test_signer();
        let manager = ConsensusManager::new(
            ConsensusConfig::default(),
            ValidatorSet::default(),
            1,
            Hash32::zero(),
            KvState::default(),
            StakeLedger::default(),
            &signer,
        )
        .unwrap();
        manager.update_validator_set(ValidatorSet::default());
    }

    #[test]
    fn test_manager_metrics_snapshot_consistent() {
        let signer = test_signer();
        let manager = ConsensusManager::new(
            ConsensusConfig::default(),
            ValidatorSet::default(),
            7,
            Hash32::zero(),
            KvState::default(),
            StakeLedger::default(),
            &signer,
        )
        .unwrap();

        let snap = manager.metrics_snapshot();
        assert_eq!(snap.height, 7);
        assert_eq!(snap.round, 0);
        assert_eq!(snap.step, 0);
        assert!((snap.quantum_purity - 1.0).abs() < 1e-10);
        assert!(snap.is_quantum_healthy);
        assert_eq!(snap.double_sign_detections, 0);
    }

    #[test]
    fn test_manager_record_commit_does_not_deadlock() {
        // Sanity: after a commit the manager should still respond to reads.
        let signer = test_signer();
        let manager = ConsensusManager::new(
            ConsensusConfig::default(),
            ValidatorSet::default(),
            1,
            Hash32::zero(),
            KvState::default(),
            StakeLedger::default(),
            &signer,
        )
        .unwrap();
        manager.record_commit(1, 0, 100);
        let _ = manager.metrics_snapshot();
        let _ = manager.quantum_state();
    }

    #[test]
    fn test_manager_record_timeout_and_transition() {
        let signer = test_signer();
        let manager = ConsensusManager::new(
            ConsensusConfig::default(),
            ValidatorSet::default(),
            1,
            Hash32::zero(),
            KvState::default(),
            StakeLedger::default(),
            &signer,
        )
        .unwrap();
        let before = manager.quantum_state().purity;
        manager.record_timeout();
        let after_timeout = manager.quantum_state().purity;
        assert!(after_timeout < before);
        manager.record_step_transition();
        let after_step = manager.quantum_state().purity;
        assert!(after_step < after_timeout);
    }

    #[test]
    fn test_manager_diagnose() {
        let signer = test_signer();
        let manager = ConsensusManager::new(
            ConsensusConfig::default(),
            ValidatorSet::default(),
            1,
            Hash32::zero(),
            KvState::default(),
            StakeLedger::default(),
            &signer,
        )
        .unwrap();
        let diag = manager.diagnose(&[], 0);
        assert!(!diag.summary.is_empty());
    }

    // ── Utility ─────────────────────────────────────────────────────────

    #[test]
    fn test_quorum_threshold() {
        assert_eq!(quorum_threshold(0), 1);
        assert_eq!(quorum_threshold(1), 1);
        assert_eq!(quorum_threshold(2), 2);
        assert_eq!(quorum_threshold(3), 3);
        assert_eq!(quorum_threshold(4), 3);
        assert_eq!(quorum_threshold(100), 67);
    }

    #[test]
    fn test_has_quorum() {
        assert!(!has_quorum(2, 4));
        assert!(has_quorum(3, 4));
        assert!(has_quorum(4, 4));
    }

    #[test]
    fn test_compute_consensus_purity() {
        assert!(compute_consensus_purity(&[0.99, 0.98, 0.97]) > 0.9);
        assert!((compute_consensus_purity(&[]) - 1.0).abs() < 1e-10);
    }

    #[test]
    fn test_compute_consensus_purity_clamps() {
        assert!((compute_consensus_purity(&[1.5, -0.5]) - 0.5).abs() < 1e-10);
        assert_eq!(compute_consensus_purity(&[f64::NAN]), 0.0);
    }

    #[test]
    fn test_compute_consensus_entropy() {
        assert!((compute_consensus_entropy(1.0) - 0.0).abs() < 1e-10);
        assert!((compute_consensus_entropy(0.0) - 0.0).abs() < 1e-10);
        assert!(compute_consensus_entropy(0.5) > 0.0);
        assert!((compute_consensus_entropy(f64::NAN) - 0.0).abs() < 1e-10);
        assert!((compute_consensus_entropy(f64::INFINITY) - 0.0).abs() < 1e-10);
    }

    #[test]
    fn test_step_to_u8() {
        assert_eq!(step_to_u8(engine::Step::Propose), 0);
        assert_eq!(step_to_u8(engine::Step::Prevote), 1);
        assert_eq!(step_to_u8(engine::Step::Precommit), 2);
        assert_eq!(step_to_u8(engine::Step::Commit), 3);
    }
}
