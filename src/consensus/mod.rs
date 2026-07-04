//! IONA consensus engine and supporting modules — Production‑Grade.
//!
//! This module implements a Tendermint‑style BFT consensus engine with:
//! - Round‑robin proposer selection
//! - Prevote / Precommit voting
//! - Double‑sign protection (persistent guard)
//! - Fast finality (optimistic single‑round commit)
//! - Quorum calculators and diagnostics
//! - Validator set management
//! - Quantum state tracking across all consensus phases
//!
//! # Quantum Consensus Architecture
//!
//! The consensus engine is modelled as an **open quantum system** where
//! each validator's state exists in a superposition of vote intentions.
//! The BFT algorithm is a **quantum error correction code** that projects
//! the system onto the |committed⟩ eigenstate when 2/3+ validators agree.
//!
//! # Production Features
//! - Unified configuration via `ConsensusConfig`.
//! - `ConsensusMetrics` with Prometheus support.
//! - `ConsensusManager` as a thread‑safe wrapper (`parking_lot::Mutex`).
//! - Integration with double‑sign guard, fast finality, and diagnostics.
//! - Structured logging with `tracing`.
//! - Full test coverage.
//!
//! # Module Overview
//!
//! | Module | Purpose | Quantum Analog |
//! |--------|---------|----------------|
//! | `engine` | BFT state machine | Hamiltonian evolution |
//! | `messages` | Proposal/Vote types | Quantum states |
//! | `double_sign` | Equivocation protection | Entanglement witness |
//! | `fast_finality` | Sub‑second commits | Projective measurement |
//! | `quorum` | Vote counting | Expectation value ⟨Q̂⟩ |
//! | `diagnostic` | Stall detection | Quantum state tomography |
//! | `validator_set` | Validator management | Basis state enumeration |
//! | `block_producer` | Block creation | State preparation |
//! | `debug_trace` | Event tracing | Measurement record |
//! | `genesis` | Chain initialisation | Ground state |∅⟩ |

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

use crate::crypto::PublicKeyBytes;
use crate::types::{Hash32, Height};
use crate::execution::KvState;
use crate::slashing::StakeLedger;
use parking_lot::Mutex;
use prometheus::{
    register_counter_vec, register_gauge, register_histogram_vec,
    CounterVec, Gauge, HistogramVec,
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use std::time::Duration;
use tracing::{debug, error, info, trace, warn};

// ── Quantum Constants ─────────────────────────────────────────────────────

/// Reduced Planck constant (natural units).
const HBAR: f64 = 1.0;

/// Minimum quorum threshold (2/3).
pub const QUORUM_NUMERATOR: u64 = 2;
pub const QUORUM_DENOMINATOR: u64 = 3;

/// Minimum coherence for healthy consensus.
pub const MIN_CONSENSUS_COHERENCE: f64 = 0.9;

/// Kraus rank for consensus quantum channels.
pub const KRAUS_RANK: usize = 4;

// ── Unified Configuration ────────────────────────────────────────────────

/// Configuration for the entire consensus subsystem.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConsensusConfig {
    /// Engine configuration.
    pub engine: engine::Config,
    /// Double‑sign guard configuration.
    pub double_sign: double_sign::GuardConfig,
    /// Fast finality configuration.
    pub fast_finality: fast_finality::FinalityConfig,
    /// Diagnostic configuration.
    pub diagnostic: diagnostic::DiagnosticConfig,
    /// Block producer configuration.
    pub block_producer: block_producer::ProducerConfig,
    /// Whether to enable metrics.
    pub enable_metrics: bool,
    /// Whether to enable quantum state tracking.
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

// ── Prometheus Metrics ──────────────────────────────────────────────────

/// Metrics for the consensus subsystem.
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
    /// Register metrics with Prometheus.
    pub fn new() -> Result<Self, prometheus::Error> {
        let height = register_gauge!("iona_consensus_height", "Current block height")?;
        let round = register_gauge!("iona_consensus_round", "Current consensus round")?;
        let step = register_gauge!("iona_consensus_step", "Current step (0=Propose,1=Prevote,2=Precommit,3=Commit)")?;
        let proposals = register_counter_vec!(
            "iona_consensus_proposals_total",
            "Proposal messages",
            &["type"]
        )?;
        let prevotes = register_counter_vec!(
            "iona_consensus_prevotes_total",
            "Prevote messages",
            &["type"]
        )?;
        let precommits = register_counter_vec!(
            "iona_consensus_precommits_total",
            "Precommit messages",
            &["type"]
        )?;
        let commits = register_counter_vec!(
            "iona_consensus_commits_total",
            "Commit events",
            &["type"]
        )?;
        let timeouts = register_counter_vec!(
            "iona_consensus_timeouts_total",
            "Timeout events",
            &["type"]
        )?;
        let double_signs = register_counter_vec!(
            "iona_consensus_double_signs_total",
            "Double-sign detections",
            &["type"]
        )?;
        let finality_lag = register_gauge!("iona_consensus_finality_lag_blocks", "Finality lag in blocks")?;
        let quantum_purity = register_gauge!("iona_consensus_quantum_purity", "Quantum purity of consensus state")?;
        let quantum_entropy = register_gauge!("iona_consensus_quantum_entropy", "Quantum entropy of consensus state")?;

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

    /// Update height.
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
        Self::new().unwrap_or_else(|_| Self {
            height: Gauge::new("iona_consensus_height", "Height").unwrap(),
            round: Gauge::new("iona_consensus_round", "Round").unwrap(),
            step: Gauge::new("iona_consensus_step", "Step").unwrap(),
            proposals: CounterVec::new(
                prometheus::Opts::new("iona_consensus_proposals_total", "Proposals"),
                &["type"],
            ).unwrap(),
            prevotes: CounterVec::new(
                prometheus::Opts::new("iona_consensus_prevotes_total", "Prevotes"),
                &["type"],
            ).unwrap(),
            precommits: CounterVec::new(
                prometheus::Opts::new("iona_consensus_precommits_total", "Precommits"),
                &["type"],
            ).unwrap(),
            commits: CounterVec::new(
                prometheus::Opts::new("iona_consensus_commits_total", "Commits"),
                &["type"],
            ).unwrap(),
            timeouts: CounterVec::new(
                prometheus::Opts::new("iona_consensus_timeouts_total", "Timeouts"),
                &["type"],
            ).unwrap(),
            double_signs: CounterVec::new(
                prometheus::Opts::new("iona_consensus_double_signs_total", "Double-signs"),
                &["type"],
            ).unwrap(),
            finality_lag: Gauge::new("iona_consensus_finality_lag_blocks", "Finality lag").unwrap(),
            quantum_purity: Gauge::new("iona_consensus_quantum_purity", "Quantum purity").unwrap(),
            quantum_entropy: Gauge::new("iona_consensus_quantum_entropy", "Quantum entropy").unwrap(),
        })
    }
}

// ── ConsensusManager ─────────────────────────────────────────────────────

/// Thread‑safe manager for the consensus subsystem.
///
/// Holds the engine, validator set, double‑sign guard, fast finality tracker,
/// and metrics. Provides a unified interface for driving consensus.
#[derive(Clone)]
pub struct ConsensusManager {
    config: Arc<ConsensusConfig>,
    metrics: Arc<ConsensusMetrics>,
    engine: Arc<Mutex<Engine<dyn crate::crypto::Verifier>>>,
    double_sign: Arc<dyn DoubleSignGuard>,
    fast_finality: Arc<Mutex<fast_finality::FinalityTracker>>,
    validator_set: Arc<Mutex<ValidatorSet>>,
    stake_ledger: Arc<Mutex<StakeLedger>>,
}

impl ConsensusManager {
    /// Create a new consensus manager.
    ///
    /// # Arguments
    /// * `config` – Unified consensus configuration.
    /// * `validator_set` – Initial validator set.
    /// * `height` – Starting height.
    /// * `prev_block_id` – Hash of the previous block.
    /// * `app_state` – Initial application state.
    /// * `stake_ledger` – Stake ledger for slashing.
    /// * `signer` – Signer for this node (for double‑sign guard).
    ///
    /// # Returns
    /// A new `ConsensusManager` instance.
    pub fn new(
        config: ConsensusConfig,
        validator_set: ValidatorSet,
        height: Height,
        prev_block_id: Hash32,
        app_state: KvState,
        stake_ledger: StakeLedger,
        signer: &dyn crate::crypto::Signer,
    ) -> Result<Self, String> {
        config.validate()?;
        let config = Arc::new(config);
        let metrics = Arc::new(ConsensusMetrics::default());

        // Create double‑sign guard.
        let guard = double_sign::DoubleSignGuard::with_config(
            "./data",
            &signer.public_key(),
            &config.double_sign,
        ).map_err(|e| format!("failed to create double‑sign guard: {}", e))?;

        // Create engine.
        let engine = engine::Engine::new(
            config.engine.clone(),
            validator_set.clone(),
            height,
            prev_block_id,
            app_state,
            stake_ledger.clone(),
            Some(guard.clone()),
        );

        // Create fast finality tracker.
        let finality = fast_finality::FinalityTracker::with_config(
            height,
            &config.fast_finality,
        );

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

    /// Get a mutable reference to the engine (for driving consensus).
    pub fn engine(&self) -> &Mutex<Engine<dyn crate::crypto::Verifier>> {
        &self.engine
    }

    /// Get the validator set.
    pub fn validator_set(&self) -> ValidatorSet {
        self.validator_set.lock().clone()
    }

    /// Update the validator set.
    pub fn update_validator_set(&self, vset: ValidatorSet) {
        let mut guard = self.validator_set.lock();
        *guard = vset;
        self.engine.lock().validator_set = guard.clone();
    }

    /// Get the stake ledger.
    pub fn stake_ledger(&self) -> StakeLedger {
        self.stake_ledger.lock().clone()
    }

    /// Record a commit event.
    pub fn record_commit(&self, height: Height, round: u32, finality_ms: u64) {
        let mut finality = self.fast_finality.lock();
        finality.record_commit(finality_ms, round, &self.config.fast_finality);
        self.metrics.record_commit("ok");
        self.metrics.set_height(height);
        self.metrics.set_round(round);
        self.metrics.set_quantum_purity(finality.purity);
        self.metrics.set_quantum_entropy(finality.entropy);
        self.metrics.set_finality_lag(0);
    }

    /// Get current metrics snapshot.
    pub fn metrics_snapshot(&self) -> ConsensusMetricsSnapshot {
        let finality = self.fast_finality.lock();
        ConsensusMetricsSnapshot {
            height: self.engine.lock().state.height,
            round: self.engine.lock().state.round,
            step: self.engine.lock().state.step as u8,
            finality_purity: finality.purity,
            finality_entropy: finality.entropy,
            is_quantum_healthy: finality.purity >= MIN_CONSENSUS_COHERENCE,
            double_sign_detections: self.double_sign.detections(),
        }
    }

    /// Get a diagnostic snapshot of the current consensus state.
    pub fn diagnose(&self, connected_validators: &[PublicKeyBytes]) -> diagnostic::ConsensusDiagnostic {
        let state = self.engine.lock().state.clone();
        let vset = self.validator_set.lock().clone();
        let config = &self.config.diagnostic;
        diagnostic::diagnose(
            &state,
            &vset,
            connected_validators,
            0,
            0,
            config,
            None,
        )
    }

    /// Get configuration.
    pub fn config(&self) -> &ConsensusConfig {
        &self.config
    }

    /// Get the double‑sign guard.
    pub fn double_sign_guard(&self) -> &dyn DoubleSignGuard {
        &*self.double_sign
    }
}

/// Snapshot of consensus metrics.
#[derive(Debug, Clone)]
pub struct ConsensusMetricsSnapshot {
    pub height: u64,
    pub round: u32,
    pub step: u8,
    pub finality_purity: f64,
    pub finality_entropy: f64,
    pub is_quantum_healthy: bool,
    pub double_sign_detections: u64,
}

// ── Consensus Statistics ────────────────────────────────────────────────

/// Aggregated statistics across all consensus components.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
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

// ── Utility Functions ────────────────────────────────────────────────────

/// Compute the quorum threshold (2/3 + 1) for a given total voting power.
///
/// This is the projective measurement threshold:
/// ```text
/// Q = ⌊total × 2 / 3⌋ + 1
/// ```
#[must_use]
pub fn quorum_threshold(total_power: u64) -> u64 {
    if total_power == 0 {
        return 1;
    }
    (total_power * QUORUM_NUMERATOR / QUORUM_DENOMINATOR) + 1
}

/// Check if a given voting power meets the quorum threshold.
#[must_use]
pub fn has_quorum(voting_power: u64, total_power: u64) -> bool {
    voting_power >= quorum_threshold(total_power)
}

/// Compute the quantum purity from a set of vote coherences.
///
/// ```text
/// γ = (1/N) Σ_i coherence_i
/// ```
#[must_use]
pub fn compute_consensus_purity(coherences: &[f64]) -> f64 {
    if coherences.is_empty() {
        return 1.0;
    }
    let avg: f64 = coherences.iter().sum::<f64>() / coherences.len() as f64;
    avg.clamp(0.0, 1.0)
}

/// Compute the von Neumann entropy from purity.
///
/// ```text
/// S = -γ ln γ - (1-γ) ln(1-γ)
/// ```
#[must_use]
pub fn compute_consensus_entropy(purity: f64) -> f64 {
    if purity >= 1.0 || purity <= 0.0 {
        return 0.0;
    }
    -purity * purity.ln() - (1.0 - purity) * (1.0 - purity).ln()
}

// ── Prelude ──────────────────────────────────────────────────────────────

/// Prelude for the consensus module.
pub mod prelude {
    pub use super::block_producer::{ProducerConfig, SimpleBlockProducer};
    pub use super::debug_trace::{ConsensusEvent, ConsensusTracer, StateRootLog, StateRootLogEntry};
    pub use super::diagnostic::{
        diagnose, ConsensusDiagnostic, DiagnosticConfig, DiagnosticStats, StallReason,
    };
    pub use super::double_sign::{vote_guard_key, DoubleSignGuard, GuardStats};
    pub use super::engine::{BlockStore, CommitCertificate, Config, ConsensusState, Engine, Outbox, Step};
    pub use super::fast_finality::{FinalityCertificate, FinalityStats, FinalityTracker, PipelineState};
    pub use super::messages::{
        proposal_sign_bytes, vote_sign_bytes, sign_bytes_fidelity,
        ConsensusMsg, MessageStats, Proposal, Vote, VoteType,
    };
    pub use super::quorum::{quorum_threshold, QuorumCalculator, VoteTally};
    pub use super::quorum_diag::QuorumDiagnostic;
    pub use super::validator_set::{Validator, ValidatorSet};
    pub use super::{
        ConsensusConfig, ConsensusManager, ConsensusMetrics, ConsensusMetricsSnapshot,
        ConsensusStats, MIN_CONSENSUS_COHERENCE, QUORUM_DENOMINATOR, QUORUM_NUMERATOR,
        has_quorum, quorum_threshold,
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

    #[test]
    fn test_quorum_threshold() {
        assert_eq!(quorum_threshold(0), 1);
        assert_eq!(quorum_threshold(1), 1);
        assert_eq!(quorum_threshold(3), 3); // 2 + 1
        assert_eq!(quorum_threshold(4), 3); // 2 + 1
        assert_eq!(quorum_threshold(100), 67); // 66 + 1
    }

    #[test]
    fn test_has_quorum() {
        assert!(!has_quorum(2, 4)); // need 3
        assert!(has_quorum(3, 4)); // exactly 3
        assert!(has_quorum(4, 4)); // all
    }

    #[test]
    fn test_compute_consensus_purity() {
        let coherences = vec![0.99, 0.98, 0.97];
        let purity = compute_consensus_purity(&coherences);
        assert!(purity > 0.9);
        assert!(purity <= 1.0);

        assert!((compute_consensus_purity(&[]) - 1.0).abs() < 1e-10);
    }

    #[test]
    fn test_compute_consensus_entropy() {
        let entropy_pure = compute_consensus_entropy(1.0);
        assert!((entropy_pure - 0.0).abs() < 1e-10);

        let entropy_mixed = compute_consensus_entropy(0.5);
        assert!(entropy_mixed > 0.0);

        let entropy_zero = compute_consensus_entropy(0.0);
        assert!((entropy_zero - 0.0).abs() < 1e-10);
    }

    #[test]
    fn test_consensus_stats_default() {
        let stats = ConsensusStats::default();
        assert_eq!(stats.blocks_committed, 0);
        assert!((stats.quantum_purity - 0.0).abs() < 1e-10);
        assert!(!stats.is_quantum_healthy);
    }

    #[test]
    fn test_config_default() {
        let config = ConsensusConfig::default();
        assert!(config.validate().is_ok());
    }

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
        );
        assert!(manager.is_ok());
        let mgr = manager.unwrap();
        assert_eq!(mgr.double_sign_guard().detections(), 0);
    }
}
