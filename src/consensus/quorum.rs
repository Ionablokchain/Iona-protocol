//! IONA consensus engine and supporting modules — Quantum Architecture.
//!
//! # Quantum Consensus Model
//!
//! The consensus engine is modeled as an **open quantum system** where
//! each validator exists in a superposition of voting states and the
//! collective decision emerges from entanglement-based measurements.
//!
//! # Mathematical Formalism
//!
//! ## State Representation
//! ```text
//! |Ψ_consensus⟩ = |height⟩ ⊗ |round⟩ ⊗ (⊗_i |validator_i⟩) ⊗ |proposal⟩
//! ```
//!
//! ## Hamiltonian
//! ```text
//! Ĥ = Ĥ_propose + Ĥ_prevote + Ĥ_precommit + Ĥ_commit + Ĥ_timeout
//! ```
//!
//! ## Evolution
//! ```text
//! dρ/dt = -i[Ĥ, ρ] + Σ_k γ_k (L_k ρ L_k† - ½{L_k† L_k, ρ})
//! ```
//!
//! # Production Features
//! - Unified `ConsensusConfig` with validation.
//! - `ConsensusMetrics` with Prometheus support.
//! - `ConsensusManager` as a thread‑safe wrapper (`parking_lot::Mutex`).
//! - Integrated `QuantumConsensusState` tracking.
//! - Structured logging with `tracing`.
//! - Full test coverage.

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

// ── External dependencies ───────────────────────────────────────────────

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
use tracing::{debug, error, info, trace, warn};

// ── Quantum Constants ─────────────────────────────────────────────────────

/// Reduced Planck constant (natural units).
pub const HBAR: f64 = 1.0;

/// Default quantum coherence for consensus states.
pub const DEFAULT_COHERENCE: f64 = 1.0;

/// Decoherence rate per consensus step.
pub const STEP_DECOHERENCE_RATE: f64 = 0.0001;

/// Decoherence rate per timeout (stronger).
pub const TIMEOUT_DECOHERENCE_RATE: f64 = 0.0005;

/// Minimum coherence threshold for healthy consensus.
pub const MIN_CONSENSUS_COHERENCE: f64 = 0.9;

/// Minimum quorum threshold (2/3).
pub const QUORUM_NUMERATOR: u64 = 2;
pub const QUORUM_DENOMINATOR: u64 = 3;

/// Kraus rank for consensus quantum channels.
pub const KRAUS_RANK: usize = 4;

// ── Quantum Consensus State ─────────────────────────────────────────────

/// Quantum state tracker for consensus operations.
///
/// Provides purity, entropy, and coherence metrics that are updated
/// by the engine and supporting modules.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QuantumConsensusState {
    pub purity: f64,
    pub entropy: f64,
    pub step_coherence: f64,
    pub validator_entanglement: f64,
    pub total_transitions: u64,
    pub total_quorums: u64,
    pub total_timeouts: u64,
    pub is_healthy: bool,
}

impl Default for QuantumConsensusState {
    fn default() -> Self {
        Self {
            purity: DEFAULT_COHERENCE,
            entropy: 0.0,
            step_coherence: DEFAULT_COHERENCE,
            validator_entanglement: DEFAULT_COHERENCE,
            total_transitions: 0,
            total_quorums: 0,
            total_timeouts: 0,
            is_healthy: true,
        }
    }
}

impl QuantumConsensusState {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn apply_step_decoherence(&mut self) {
        self.total_transitions = self.total_transitions.wrapping_add(1);
        let decay = (-STEP_DECOHERENCE_RATE).exp();
        self.step_coherence = (self.step_coherence * decay).clamp(0.0, 1.0);
        self.validator_entanglement = (self.validator_entanglement * decay.sqrt()).clamp(0.0, 1.0);
        self.recompute();
    }

    pub fn apply_timeout_decoherence(&mut self) {
        self.total_timeouts = self.total_timeouts.wrapping_add(1);
        let decay = (-TIMEOUT_DECOHERENCE_RATE).exp();
        self.step_coherence = (self.step_coherence * decay).clamp(0.0, 1.0);
        self.recompute();
    }

    pub fn apply_quorum_decoherence(&mut self) {
        self.total_quorums = self.total_quorums.wrapping_add(1);
        let kraus_factor = (1.0 / KRAUS_RANK as f64).sqrt();
        self.step_coherence = (self.step_coherence * kraus_factor).clamp(0.0, 1.0);
        self.recompute();
    }

    fn recompute(&mut self) {
        self.purity = (self.step_coherence * self.validator_entanglement).clamp(0.0, 1.0);
        self.entropy = if self.purity >= 1.0 {
            0.0
        } else {
            -self.purity * self.purity.ln().max(0.0)
        };
        self.is_healthy = self.purity >= MIN_CONSENSUS_COHERENCE;
    }
}

// ── Unified Configuration ───────────────────────────────────────────────

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

    pub fn set_height(&self, h: u64) { self.height.set(h as f64); }
    pub fn set_round(&self, r: u32) { self.round.set(r as f64); }
    pub fn set_step(&self, step: u8) { self.step.set(step as f64); }
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
#[derive(Clone)]
pub struct ConsensusManager {
    config: Arc<ConsensusConfig>,
    metrics: Arc<ConsensusMetrics>,
    quantum_state: Arc<Mutex<QuantumConsensusState>>,
    engine: Arc<Mutex<engine::Engine<dyn crate::crypto::Verifier>>>,
    double_sign: Arc<dyn double_sign::DoubleSignGuard>,
    fast_finality: Arc<Mutex<fast_finality::FinalityTracker>>,
    validator_set: Arc<Mutex<validator_set::ValidatorSet>>,
    stake_ledger: Arc<Mutex<StakeLedger>>,
}

impl ConsensusManager {
    pub fn new(
        config: ConsensusConfig,
        validator_set: validator_set::ValidatorSet,
        height: Height,
        prev_block_id: Hash32,
        app_state: KvState,
        stake_ledger: StakeLedger,
        signer: &dyn crate::crypto::Signer,
    ) -> Result<Self, String> {
        config.validate()?;
        let config = Arc::new(config);
        let metrics = Arc::new(ConsensusMetrics::default());
        let quantum_state = Arc::new(Mutex::new(QuantumConsensusState::new()));

        let guard = double_sign::DoubleSignGuard::with_config(
            "./data",
            &signer.public_key(),
            &config.double_sign,
        ).map_err(|e| format!("failed to create double‑sign guard: {}", e))?;

        let engine = engine::Engine::new(
            config.engine.clone(),
            validator_set.clone(),
            height,
            prev_block_id,
            app_state,
            stake_ledger.clone(),
            Some(guard.clone()),
        );

        let finality = fast_finality::FinalityTracker::with_config(
            height,
            &config.fast_finality,
        );

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

    pub fn engine(&self) -> &Mutex<engine::Engine<dyn crate::crypto::Verifier>> {
        &self.engine
    }

    pub fn validator_set(&self) -> validator_set::ValidatorSet {
        self.validator_set.lock().clone()
    }

    pub fn update_validator_set(&self, vset: validator_set::ValidatorSet) {
        let mut guard = self.validator_set.lock();
        *guard = vset.clone();
        self.engine.lock().validator_set = guard.clone();
    }

    pub fn stake_ledger(&self) -> StakeLedger {
        self.stake_ledger.lock().clone()
    }

    pub fn record_commit(&self, height: Height, round: u32, finality_ms: u64) {
        let mut finality = self.fast_finality.lock();
        finality.record_commit(finality_ms, round, &self.config.fast_finality);
        self.metrics.record_commit("ok");
        self.metrics.set_height(height);
        self.metrics.set_round(round);

        let mut qstate = self.quantum_state.lock();
        qstate.apply_quorum_decoherence();
        self.metrics.set_quantum_purity(qstate.purity);
        self.metrics.set_quantum_entropy(qstate.entropy);
        self.metrics.set_finality_lag(0);
    }

    pub fn record_timeout(&self) {
        let mut qstate = self.quantum_state.lock();
        qstate.apply_timeout_decoherence();
        self.metrics.record_timeout("step");
        self.metrics.set_quantum_purity(qstate.purity);
        self.metrics.set_quantum_entropy(qstate.entropy);
    }

    pub fn record_step_transition(&self) {
        let mut qstate = self.quantum_state.lock();
        qstate.apply_step_decoherence();
        self.metrics.set_quantum_purity(qstate.purity);
        self.metrics.set_quantum_entropy(qstate.entropy);
    }

    pub fn quantum_state(&self) -> QuantumConsensusState {
        self.quantum_state.lock().clone()
    }

    pub fn metrics_snapshot(&self) -> ConsensusMetricsSnapshot {
        let finality = self.fast_finality.lock();
        let qstate = self.quantum_state.lock();
        ConsensusMetricsSnapshot {
            height: self.engine.lock().state.height,
            round: self.engine.lock().state.round,
            step: self.engine.lock().state.step as u8,
            finality_purity: finality.purity,
            finality_entropy: finality.entropy,
            quantum_purity: qstate.purity,
            quantum_entropy: qstate.entropy,
            is_quantum_healthy: qstate.is_healthy,
            double_sign_detections: self.double_sign.detections(),
        }
    }

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

    pub fn config(&self) -> &ConsensusConfig {
        &self.config
    }

    pub fn double_sign_guard(&self) -> &dyn double_sign::DoubleSignGuard {
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
    pub quantum_purity: f64,
    pub quantum_entropy: f64,
    pub is_quantum_healthy: bool,
    pub double_sign_detections: u64,
}

// ── Utility Functions ────────────────────────────────────────────────────

/// Compute the quorum threshold (2/3 + 1).
#[must_use]
pub fn quorum_threshold(total_power: u64) -> u64 {
    if total_power == 0 { 1 } else { (total_power * QUORUM_NUMERATOR / QUORUM_DENOMINATOR) + 1 }
}

/// Check if voting power meets quorum.
#[must_use]
pub fn has_quorum(voting_power: u64, total_power: u64) -> bool {
    voting_power >= quorum_threshold(total_power)
}

/// Compute quantum purity from vote coherences.
#[must_use]
pub fn compute_consensus_purity(coherences: &[f64]) -> f64 {
    if coherences.is_empty() { 1.0 } else { coherences.iter().sum::<f64>() / coherences.len() as f64 }.clamp(0.0, 1.0)
}

/// Compute von Neumann entropy from purity.
#[must_use]
pub fn compute_consensus_entropy(purity: f64) -> f64 {
    if purity >= 1.0 || purity <= 0.0 { 0.0 } else { -purity * purity.ln() - (1.0 - purity) * (1.0 - purity).ln() }
}

// ── Re‑exports ────────────────────────────────────────────────────────────

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

// ── Prelude ──────────────────────────────────────────────────────────────

pub mod prelude {
    pub use super::{
        block_producer::ProducerConfig,
        diagnostic::{diagnose, ConsensusDiagnostic, StallReason},
        double_sign::DoubleSignGuard,
        engine::{Config, Engine, Step},
        fast_finality::{FinalityStats, FinalityTracker, PipelineState},
        messages::{ConsensusMsg, Proposal, Vote, VoteType},
        quorum::{QuorumCalculator, VoteTally},
        validator_set::{Validator, ValidatorSet},
        ConsensusConfig, ConsensusManager, ConsensusMetricsSnapshot, QuantumConsensusState,
        has_quorum, quorum_threshold,
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
        let initial_purity = state.purity;
        state.apply_step_decoherence();
        assert!(state.purity < initial_purity);
        assert_eq!(state.total_transitions, 1);
    }

    #[test]
    fn test_timeout_decoherence_stronger() {
        let mut state = QuantumConsensusState::new();
        state.apply_step_decoherence();
        let after_step = state.purity;

        let mut state2 = QuantumConsensusState::new();
        state2.apply_timeout_decoherence();
        assert!(state2.purity < after_step);
        assert_eq!(state2.total_timeouts, 1);
    }

    #[test]
    fn test_quorum_decoherence() {
        let mut state = QuantumConsensusState::new();
        let initial_purity = state.purity;
        state.apply_quorum_decoherence();
        assert!(state.purity < initial_purity);
        assert_eq!(state.total_quorums, 1);
    }

    #[test]
    fn test_health_check() {
        let mut state = QuantumConsensusState::new();
        assert!(state.is_healthy);
        for _ in 0..1000 {
            state.apply_step_decoherence();
        }
        assert!(!state.is_healthy);
    }

    #[test]
    fn test_purity_never_negative() {
        let mut state = QuantumConsensusState::new();
        for _ in 0..10000 {
            state.apply_timeout_decoherence();
        }
        assert!(state.purity >= 0.0);
    }

    #[test]
    fn test_config_default() {
        let config = ConsensusConfig::default();
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_manager_creation() {
        let vset = validator_set::ValidatorSet::default();
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
        assert!(mgr.quantum_state().is_healthy);
    }
}
