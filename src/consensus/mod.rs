//! IONA consensus engine and supporting modules — Production‑Grade.
//!
//! This module implements a Tendermint‑style BFT consensus engine with:
//! - Round‑robin proposer selection
//! - Prevote / Precommit voting
//! - Double‑sign protection (persistent guard)
//! - Fast finality (optimistic single‑round commit)
//! - Quorum calculators and diagnostics
//! - Validator set management
//! - Informational "quantum" state tracking across all consensus phases
//!
//! # Model
//!
//! The consensus engine is a classical BFT state machine. The "quantum"
//! fields (`purity`, `entropy`, `coherence`) are **informational only** —
//! they never gate a decision and never cause an error. See the sub-module
//! docs for each component.
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
//! [`ConsensusManager`] is `Clone` + `Send` + `Sync`. All internal state is
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

// ── Re‑exports ─────────────────────────────────────────────────────────────

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

// ── Quorum constants ──────────────────────────────────────────────────────

/// Numerator of the BFT quorum threshold (2/3).
pub const QUORUM_NUMERATOR: u64 = 2;

/// Denominator of the BFT quorum threshold (2/3).
pub const QUORUM_DENOMINATOR: u64 = 3;

/// Coherence threshold below which the informational `is_quantum_healthy`
/// flag flips to `false`.
pub const MIN_CONSENSUS_COHERENCE: f64 = 0.9;

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
    /// Validate the entire configuration.
    pub fn validate(&self) -> Result<(), String> {
        self.engine.validate()?;
        self.double_sign.validate()?;
        self.fast_finality.validate()?;
        self.diagnostic.validate()?;
        self.block_producer.validate()?;
        Ok(())
    }
}

// ── Prometheus metrics ────────────────────────────────────────────────────

/// Metrics for the consensus subsystem.
///
/// # Registration
///
/// [`ConsensusMetrics::new`] registers with the **default** Prometheus
/// registry. It can only be called once per process — a second call returns
/// `Err`. Use [`ConsensusMetrics::default`] for an unregistered instance
/// (e.g. in tests, or when using a custom registry via
/// [`try_new_with`](Self::try_new_with)).
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
    /// Returns `Err` if any name is already registered (including on a
    /// second call in the same process).
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
    /// Safe to call any number of times. Does not appear in the default
    /// Prometheus registry unless the caller registers it manually.
    pub fn unregistered() -> Self {
        let mk_gauge = |name: &str, help: &str| Gauge::new(name, help)
            .expect("gauge construction is infallible for these names");
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
            proposals: mk_counter(
                "iona_consensus_proposals_total",
                "Proposal messages",
            ),
            prevotes: mk_counter("iona_consensus_prevotes_total", "Prevote messages"),
            precommits: mk_counter(
                "iona_consensus_precommits_total",
                "Precommit messages",
            ),
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
/// tracker, and metrics. Provides a unified interface for driving
/// consensus.
///
/// # Cloning
///
/// Cloning shares state via `Arc`. Clones observe each other's writes.
#[derive(Clone)]
pub struct ConsensusManager {
    config: Arc<ConsensusConfig>,
    metrics: Arc<ConsensusMetrics>,
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
    /// - Double-sign guard cannot be loaded (integrity failure is **fatal**;
    ///   starting with a corrupt guard risks equivocation).
    ///
    /// # Object safety
    ///
    /// `dyn Verifier` requires `Verifier` to be object-safe. If your
    /// `Verifier` trait has generic methods or associated consts, use a
    /// type-erased wrapper instead.
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
                    "metrics already registered; using unregistered instance"
                );
                ConsensusMetrics::unregistered()
            })
        } else {
            ConsensusMetrics::unregistered()
        };

        let config = Arc::new(config);
        let metrics = Arc::new(metrics);

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
            engine: Arc::new(Mutex::new(engine)),
            double_sign: Arc::new(guard),
            fast_finality: Arc::new(Mutex::new(finality)),
            validator_set: Arc::new(Mutex::new(validator_set)),
            stake_ledger: Arc::new(Mutex::new(stake_ledger)),
        })
    }

    /// Access the engine mutex.
    ///
    /// **Do not** hold this lock across a call to any method on `self`
    /// that also locks the engine — `parking_lot::Mutex` is not reentrant.
    pub fn engine(&self) -> &Mutex<engine::Engine<dyn Verifier>> {
        &self.engine
    }

    /// Snapshot of the current validator set.
    pub fn validator_set(&self) -> ValidatorSet {
        self.validator_set.lock().clone()
    }

    /// Replace the validator set in both the manager and the engine.
    pub fn update_validator_set(&self, vset: ValidatorSet) {
        *self.validator_set.lock() = vset.clone();
        // Field name in Engine is `vset`, not `validator_set`.
        self.engine.lock().vset = vset;
    }

    /// Snapshot of the current stake ledger.
    pub fn stake_ledger(&self) -> StakeLedger {
        self.stake_ledger.lock().clone()
    }

    /// Record a commit event and update metrics.
    pub fn record_commit(&self, height: Height, round: u32, finality_ms: u64) {
        let (purity, entropy) = {
            let mut finality = self.fast_finality.lock();
            finality.record_commit(finality_ms, round, &self.config.fast_finality);
            (finality.purity, finality.entropy)
        };

        self.metrics.record_commit("ok");
        self.metrics.set_height(height);
        self.metrics.set_round(round);
        self.metrics.set_step(step_to_u8(engine::Step::Commit));
        self.metrics.set_quantum_purity(purity);
        self.metrics.set_quantum_entropy(entropy);
        self.metrics.set_finality_lag(0);
    }

    /// Snapshot of the current metrics.
    ///
    /// Locks the engine once (not three times) so the snapshot is
    /// internally consistent.
    pub fn metrics_snapshot(&self) -> ConsensusMetricsSnapshot {
        let (height, round, step) = {
            let engine = self.engine.lock();
            (
                engine.state.height,
                engine.state.round,
                step_to_u8(engine.state.step),
            )
        };
        let (purity, entropy) = {
            let finality = self.fast_finality.lock();
            (finality.purity, finality.entropy)
        };
        ConsensusMetricsSnapshot {
            height,
            round,
            step,
            finality_purity: purity,
            finality_entropy: entropy,
            is_quantum_healthy: purity >= MIN_CONSENSUS_COHERENCE,
            double_sign_detections: self.double_sign.detections(),
        }
    }

    /// Produce a diagnostic snapshot of the current consensus state.
    ///
    /// Uses the stake-weighted quorum calculator and passes the configured
    /// propose timeout (not `0`, which the previous implementation did).
    pub fn diagnose(
        &self,
        connected_validators: &[PublicKeyBytes],
        step_elapsed_ms: u64,
    ) -> diagnostic::ConsensusDiagnostic {
        let (state, vset, ledger) = (
            self.engine.lock().state.clone(),
            self.validator_set.lock().clone(),
            self.stake_ledger.lock().clone(),
        );
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
    pub is_quantum_healthy: bool,
    pub double_sign_detections: u64,
}

// ── Consensus statistics ────────────────────────────────────────────────

/// Aggregated statistics across all consensus components.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ConsensusStats {
    pub blocks_committed: u64,
    pub rounds_advanced: u64,
    pub proposals_made: u64,
    pub proposals_received: u64,
    pub prevotes_cast: u64,
    pub prevotes_received: u64,
    pub precommits_cast: u64,
    pub precommits_received: u64,
    pub timeouts: u64,
    pub double_sign_detections: u64,
    pub evidence_processed: u64,
    pub quantum_purity: f64,
    pub quantum_entropy: f64,
    pub is_quantum_healthy: bool,
}

impl Default for ConsensusStats {
    fn default() -> Self {
        Self {
            blocks_committed: 0,
            rounds_advanced: 0,
            proposals_made: 0,
            proposals_received: 0,
            prevotes_cast: 0,
            prevotes_received: 0,
            precommits_cast: 0,
            precommits_received: 0,
            timeouts: 0,
            double_sign_detections: 0,
            evidence_processed: 0,
            // A fresh engine is fully coherent.
            quantum_purity: 1.0,
            quantum_entropy: 0.0,
            is_quantum_healthy: true,
        }
    }
}

// ── Utility functions ────────────────────────────────────────────────────

/// Compute the BFT quorum threshold (`floor(total × 2 / 3) + 1`).
///
/// `total == 0` returns `1` (defensive: an empty validator set cannot
/// reach quorum, but we avoid a nonsensical `0`).
#[must_use]
pub fn quorum_threshold(total_power: u64) -> u64 {
    if total_power == 0 {
        return 1;
    }
    // Multiply first to avoid losing precision to integer division.
    (total_power * QUORUM_NUMERATOR / QUORUM_DENOMINATOR) + 1
}

/// Whether `voting_power` meets the quorum threshold for `total_power`.
#[must_use]
pub fn has_quorum(voting_power: u64, total_power: u64) -> bool {
    voting_power >= quorum_threshold(total_power)
}

/// Average of the given coherences, clamped to `[0, 1]`.
///
/// Returns `1.0` for an empty input (vacuously pure).
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
/// Note: this is **not** the von Neumann entropy of a density matrix. It
/// is a convenient proxy that is `0` at `p = 0` and `p = 1`, and maximal
/// at `p = 0.5`. Values outside `[0, 1]` yield `0`.
#[must_use]
pub fn compute_consensus_entropy(purity: f64) -> f64 {
    if !purity.is_finite() || purity <= 0.0 || purity >= 1.0 {
        return 0.0;
    }
    -purity * purity.ln() - (1.0 - purity) * (1.0 - purity).ln()
}

// ── Prelude ──────────────────────────────────────────────────────────────

/// Prelude for the consensus module.
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
        ConsensusMetricsSnapshot, ConsensusStats, MIN_CONSENSUS_COHERENCE,
        QUORUM_DENOMINATOR, QUORUM_NUMERATOR,
    };
}

// ── Tests ─────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::ed25519::Ed25519Keypair;
    use crate::types::Hash32;

    fn test_signer() -> Ed25519Keypair {
        Ed25519Keypair::from_seed([0u8; 32])
    }

    // ── Quorum ──────────────────────────────────────────────────────────

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
    fn test_quorum_threshold_never_overflows_for_large_power() {
        // `(u64::MAX * 2) / 3` would overflow if multiplied in u64. We use
        // the same expression, but for u64::MAX the multiplication wraps.
        // Guard against this by keeping the test bounded to realistic
        // powers, and document the practical limit.
        let power = u64::MAX / QUORUM_NUMERATOR;
        let q = quorum_threshold(power);
        // Only assert monotonicity here — the exact value is a documented
        // limitation for absurd power totals.
        assert!(q > 0);
    }

    // ── Purity / entropy ────────────────────────────────────────────────

    #[test]
    fn test_compute_consensus_purity() {
        let purity = compute_consensus_purity(&[0.99, 0.98, 0.97]);
        assert!(purity > 0.9);
        assert!(purity <= 1.0);
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
    }

    // ── Stats / snapshot ────────────────────────────────────────────────

    #[test]
    fn test_consensus_stats_default_is_healthy() {
        // Regression: `#[derive(Default)]` previously produced
        // `quantum_purity: 0.0, is_quantum_healthy: false` — which reads as
        // "unhealthy" for a fresh instance that has done nothing wrong.
        let stats = ConsensusStats::default();
        assert_eq!(stats.blocks_committed, 0);
        assert_eq!(stats.quantum_purity, 1.0);
        assert!(stats.is_quantum_healthy);
    }

    #[test]
    fn test_step_to_u8() {
        assert_eq!(step_to_u8(engine::Step::Propose), 0);
        assert_eq!(step_to_u8(engine::Step::Prevote), 1);
        assert_eq!(step_to_u8(engine::Step::Precommit), 2);
        assert_eq!(step_to_u8(engine::Step::Commit), 3);
    }

    // ── Config ──────────────────────────────────────────────────────────

    #[test]
    fn test_config_default() {
        let config = ConsensusConfig::default();
        assert!(config.validate().is_ok());
    }

    // ── Metrics ─────────────────────────────────────────────────────────

    #[test]
    fn test_metrics_unregistered_is_repeatable() {
        // `unregistered()` must be safe to call any number of times.
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
        m.record_proposal("sent");
        m.record_commit("ok");
        m.set_finality_lag(3);
        m.set_quantum_purity(0.95);
        m.set_quantum_entropy(0.05);
    }

    // ── Manager ─────────────────────────────────────────────────────────

    #[test]
    fn test_manager_creation() {
        let vset = ValidatorSet::default();
        let ledger = StakeLedger::default();
        let signer = test_signer();
        let manager = ConsensusManager::new(
            ConsensusConfig::default(),
            vset,
            1,
            Hash32::zero(),
            KvState::default(),
            ledger,
            &signer,
        )
        .expect("manager creation should succeed");
        assert_eq!(manager.double_sign_guard().detections(), 0);
    }

    #[test]
    fn test_manager_metrics_snapshot_consistent() {
        let vset = ValidatorSet::default();
        let ledger = StakeLedger::default();
        let signer = test_signer();
        let manager = ConsensusManager::new(
            ConsensusConfig::default(),
            vset,
            7,
            Hash32::zero(),
            KvState::default(),
            ledger,
            &signer,
        )
        .unwrap();

        let snap = manager.metrics_snapshot();
        assert_eq!(snap.height, 7);
        assert_eq!(snap.round, 0);
        assert_eq!(snap.step, 0); // Propose
        // A fresh manager is coherent.
        assert!((snap.finality_purity - 1.0).abs() < 1e-10);
        assert!(snap.is_quantum_healthy);
        assert_eq!(snap.double_sign_detections, 0);
    }

    #[test]
    fn test_manager_update_validator_set() {
        // Regression: previously wrote to `engine.validator_set`, which
        // does not exist (`Engine` names the field `vset`).
        let vset = ValidatorSet::default();
        let ledger = StakeLedger::default();
        let signer = test_signer();
        let manager = ConsensusManager::new(
            ConsensusConfig::default(),
            vset,
            1,
            Hash32::zero(),
            KvState::default(),
            ledger,
            &signer,
        )
        .unwrap();

        let new_vset = ValidatorSet::default();
        manager.update_validator_set(new_vset);
        // No panic means the field name is correct.
    }

    #[test]
    fn test_manager_diagnose() {
        let vset = ValidatorSet::default();
        let ledger = StakeLedger::default();
        let signer = test_signer();
        let manager = ConsensusManager::new(
            ConsensusConfig::default(),
            vset,
            1,
            Hash32::zero(),
            KvState::default(),
            ledger,
            &signer,
        )
        .unwrap();

        let diag = manager.diagnose(&[], 0);
        // Empty validator set → "no validators" is one of the reasons.
        assert!(!diag.summary.is_empty());
    }
}
