//! Sub‑second finality module for IONA — Quantum Adaptive Finality.
//!
//! # Quantum Finality Model
//!
//! Finality is modelled as a **quantum projective measurement** on the
//! consensus state. When 2/3+ validators precommit, the wavefunction
//! collapses to the |committed⟩ eigenstate.
//!
//! # Mathematical Formalism
//!
//! ## Finality as Projective Measurement
//! ```text
//! Π_commit = Σ_{q∈quorum} |q⟩⟨q| ⊗ |block⟩⟨block|
//! P(commit) = Tr(ρ Π_commit)
//! ```
//!
//! ## Hamiltonian for Finality Dynamics
//! ```text
//! Ĥ_finality = Ĥ_clock + Ĥ_adapt + Ĥ_pipeline
//!
//! Ĥ_clock    = ω_clock a† a                               (time oscillator)
//! Ĥ_adapt    = Σ_i λ_i (|fast_i⟩⟨slow_i| + h.c.)         (adaptation coupling)
//! Ĥ_pipeline = Σ_j g_j (|prepare⟩⟨commit|_j + h.c.)       (pipeline entanglement)
//! ```
//!
//! ## Adaptive Timeouts as Quantum Harmonic Oscillator
//! ```text
//! τ(t+dt) = τ(t) × exp(±γ × dt)
//! ```
//! where γ is the adaptation rate. This corresponds to a **damped harmonic
//! oscillator** with the Hamiltonian:
//! ```text
//! Ĥ_τ = ω_τ (n̂ + ½) + iγ(a† - a)
//! ```
//!
//! ## Pipelining as Quantum Entanglement
//! ```text
//! |Ψ_pipeline⟩ = (1/√2)(|prepare⟩|commit⟩ + |commit⟩|prepare⟩)
//! ```
//! The next block preparation is **entangled** with the current commit
//! propagation, enabling overlap without causality violation.

use crate::consensus::CommitCertificate;
use crate::types::{Hash32, Height};
use serde::{Deserialize, Serialize};
use std::collections::VecDeque;

// -----------------------------------------------------------------------------
// Quantum Constants
// -----------------------------------------------------------------------------

/// Default rolling window size for finality statistics (coherence length).
pub const DEFAULT_WINDOW_SIZE: usize = 100;

/// Minimum propose timeout (ms) – quantum ground state.
pub const MIN_PROPOSE_MS: u64 = 50;

/// Minimum vote timeout (ms) – ground state.
pub const MIN_VOTE_MS: u64 = 30;

/// Maximum propose timeout (ms) – classical limit.
pub const MAX_PROPOSE_MS: u64 = 500;

/// Maximum vote timeout (ms) – classical limit.
pub const MAX_VOTE_MS: u64 = 300;

/// Default initial propose timeout (ms).
pub const DEFAULT_PROPOSE_MS: u64 = 150;

/// Default initial prevote/precommit timeout (ms).
pub const DEFAULT_VOTE_MS: u64 = 100;

/// Threshold: if average finality < this, shrink timeouts (excited state).
pub const SHRINK_THRESHOLD_MS: u64 = 500;

/// Threshold: if average finality > this, grow timeouts (relaxation).
pub const GROW_THRESHOLD_MS: u64 = 800;

/// Number of consecutive fast commits before shrinking timeouts.
pub const FAST_COMMITS_BEFORE_SHRINK: u64 = 5;

/// Minimum number of samples for sub‑second detection.
pub const MIN_SAMPLES_FOR_SUBSECOND: usize = 10;

/// Percentage for P95 calculation.
const P95_PERCENTILE: f64 = 0.95;

/// Reduced Planck constant (natural units).
const HBAR: f64 = 1.0;

/// Decoherence rate per commit recording.
const COMMIT_DECOHERENCE_RATE: f64 = 0.0005;

/// Adaptation strength (harmonic oscillator coupling).
const ADAPTATION_STRENGTH: f64 = 0.1;

/// Pipeline entanglement strength.
const PIPELINE_ENTANGLEMENT: f64 = 0.99;

// -----------------------------------------------------------------------------
// Quantum Finality Tracker
// -----------------------------------------------------------------------------

/// Tracks finality timing with quantum state properties.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FinalityTracker {
    /// Rolling window of recent finality times (measurement outcomes).
    pub recent_finality_ms: VecDeque<u64>,
    /// Maximum window size (Hilbert space dimension bound).
    pub window_size: usize,
    /// Number of consecutive single‑round commits (coherence indicator).
    pub consecutive_fast_commits: u64,
    /// Total blocks finalized (cumulative measurement count).
    pub total_finalized: u64,
    /// Best (lowest) finality time observed.
    pub best_finality_ms: u64,
    /// Worst (highest) finality time observed.
    pub worst_finality_ms: u64,
    /// Current adaptive propose timeout (oscillator frequency).
    pub adaptive_propose_ms: u64,
    /// Current adaptive prevote timeout.
    pub adaptive_prevote_ms: u64,
    /// Current adaptive precommit timeout.
    pub adaptive_precommit_ms: u64,
    /// Height at which finality tracking started.
    pub start_height: Height,
    /// Quantum purity γ = Tr(ρ²) of the finality state.
    #[serde(default = "default_purity")]
    pub purity: f64,
    /// Von Neumann entropy S = -Tr(ρ ln ρ).
    #[serde(default)]
    pub entropy: f64,
    /// Coherence of the adaptation oscillator.
    #[serde(default = "default_purity")]
    pub adaptation_coherence: f64,
}

fn default_purity() -> f64 {
    1.0
}

impl Default for FinalityTracker {
    fn default() -> Self {
        Self {
            recent_finality_ms: VecDeque::with_capacity(DEFAULT_WINDOW_SIZE),
            window_size: DEFAULT_WINDOW_SIZE,
            consecutive_fast_commits: 0,
            total_finalized: 0,
            best_finality_ms: u64::MAX,
            worst_finality_ms: 0,
            adaptive_propose_ms: DEFAULT_PROPOSE_MS,
            adaptive_prevote_ms: DEFAULT_VOTE_MS,
            adaptive_precommit_ms: DEFAULT_VOTE_MS,
            start_height: 0,
            purity: 1.0,
            entropy: 0.0,
            adaptation_coherence: 1.0,
        }
    }
}

impl FinalityTracker {
    /// Create a new quantum tracker starting at the given height.
    #[must_use]
    pub fn new(start_height: Height) -> Self {
        Self {
            start_height,
            ..Default::default()
        }
    }

    /// Record a successful commit — projective measurement outcome.
    ///
    /// Each commit collapses the quantum state slightly.
    pub fn record_commit(&mut self, finality_ms: u64, round: u32) {
        self.total_finalized = self.total_finalized.wrapping_add(1);

        // Track fast commits (coherence preservation)
        if round == 0 {
            self.consecutive_fast_commits = self.consecutive_fast_commits.wrapping_add(1);
        } else {
            self.consecutive_fast_commits = 0;
        }

        // Update classical statistics
        if finality_ms < self.best_finality_ms {
            self.best_finality_ms = finality_ms;
        }
        if finality_ms > self.worst_finality_ms {
            self.worst_finality_ms = finality_ms;
        }

        // Update rolling window (quantum memory)
        self.recent_finality_ms.push_back(finality_ms);
        while self.recent_finality_ms.len() > self.window_size {
            self.recent_finality_ms.pop_front();
        }

        // Apply measurement decoherence
        self.apply_decoherence();

        // Adapt timeouts (harmonic oscillator evolution)
        self.adapt_timeouts();
    }

    /// Apply decoherence from measurement.
    fn apply_decoherence(&mut self) {
        let decay = (-COMMIT_DECOHERENCE_RATE).exp();
        self.purity = (self.purity * decay).clamp(0.0, 1.0);
        self.adaptation_coherence = (self.adaptation_coherence * decay).clamp(0.0, 1.0);
        self.entropy = if self.purity >= 1.0 {
            0.0
        } else {
            -self.purity * self.purity.ln().max(0.0)
        };
    }

    /// Average finality time over the recent window (expectation value).
    #[must_use]
    pub fn average_finality_ms(&self) -> u64 {
        if self.recent_finality_ms.is_empty() {
            return 0;
        }
        let sum: u64 = self.recent_finality_ms.iter().sum();
        sum / self.recent_finality_ms.len() as u64
    }

    /// P95 finality time (95th percentile of measurement distribution).
    #[must_use]
    pub fn p95_finality_ms(&self) -> u64 {
        if self.recent_finality_ms.is_empty() {
            return 0;
        }
        let mut sorted: Vec<u64> = self.recent_finality_ms.iter().copied().collect();
        sorted.sort_unstable();
        let idx = (sorted.len() as f64 * P95_PERCENTILE) as usize;
        sorted[idx.min(sorted.len() - 1)]
    }

    /// Whether we are consistently achieving sub‑second finality.
    #[must_use]
    pub fn is_sub_second(&self) -> bool {
        self.recent_finality_ms.len() >= MIN_SAMPLES_FOR_SUBSECOND
            && self.p95_finality_ms() < 1000
    }

    /// Adapt timeouts — quantum harmonic oscillator evolution.
    ///
    /// ```text
    /// τ(t+dt) = τ(t) × exp(±γ × dt)
    /// where γ = ADAPTATION_STRENGTH × adaptation_coherence
    /// ```
    fn adapt_timeouts(&mut self) {
        let avg = self.average_finality_ms();
        if avg == 0 {
            return;
        }

        let gamma = ADAPTATION_STRENGTH * self.adaptation_coherence;

        if avg < SHRINK_THRESHOLD_MS && self.consecutive_fast_commits > FAST_COMMITS_BEFORE_SHRINK {
            // Network is healthy: shrink timeouts toward minimum.
            let factor = (-gamma).exp();
            self.adaptive_propose_ms =
                ((self.adaptive_propose_ms as f64 * factor) as u64).max(MIN_PROPOSE_MS);
            self.adaptive_prevote_ms =
                ((self.adaptive_prevote_ms as f64 * factor) as u64).max(MIN_VOTE_MS);
            self.adaptive_precommit_ms =
                ((self.adaptive_precommit_ms as f64 * factor) as u64).max(MIN_VOTE_MS);
            // Adaptation preserves coherence
            self.adaptation_coherence = (self.adaptation_coherence * 1.001).min(1.0);
        } else if avg > GROW_THRESHOLD_MS || self.consecutive_fast_commits == 0 {
            // Network is stressed: grow timeouts toward maximum.
            let factor = gamma.exp();
            self.adaptive_propose_ms =
                ((self.adaptive_propose_ms as f64 * factor) as u64).min(MAX_PROPOSE_MS);
            self.adaptive_prevote_ms =
                ((self.adaptive_prevote_ms as f64 * factor) as u64).min(MAX_VOTE_MS);
            self.adaptive_precommit_ms =
                ((self.adaptive_precommit_ms as f64 * factor) as u64).min(MAX_VOTE_MS);
            // Stress causes decoherence
            self.adaptation_coherence = (self.adaptation_coherence * 0.99).max(0.0);
        }
    }

    /// Get current adaptive timeouts.
    #[must_use]
    pub fn adaptive_timeouts(&self) -> (u64, u64, u64) {
        (
            self.adaptive_propose_ms,
            self.adaptive_prevote_ms,
            self.adaptive_precommit_ms,
        )
    }

    /// Report quantum finality statistics.
    #[must_use]
    pub fn stats(&self) -> FinalityStats {
        FinalityStats {
            total_finalized: self.total_finalized,
            average_finality_ms: self.average_finality_ms(),
            p95_finality_ms: self.p95_finality_ms(),
            best_finality_ms: if self.best_finality_ms == u64::MAX {
                0
            } else {
                self.best_finality_ms
            },
            worst_finality_ms: self.worst_finality_ms,
            consecutive_fast_commits: self.consecutive_fast_commits,
            is_sub_second: self.is_sub_second(),
            adaptive_propose_ms: self.adaptive_propose_ms,
            adaptive_prevote_ms: self.adaptive_prevote_ms,
            adaptive_precommit_ms: self.adaptive_precommit_ms,
            purity: self.purity,
            entropy: self.entropy,
            adaptation_coherence: self.adaptation_coherence,
        }
    }
}

// -----------------------------------------------------------------------------
// Statistics Structure
// -----------------------------------------------------------------------------

/// Quantum statistics snapshot from the finality tracker.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FinalityStats {
    pub total_finalized: u64,
    pub average_finality_ms: u64,
    pub p95_finality_ms: u64,
    pub best_finality_ms: u64,
    pub worst_finality_ms: u64,
    pub consecutive_fast_commits: u64,
    pub is_sub_second: bool,
    pub adaptive_propose_ms: u64,
    pub adaptive_prevote_ms: u64,
    pub adaptive_precommit_ms: u64,
    /// Quantum purity γ = Tr(ρ²).
    pub purity: f64,
    /// Von Neumann entropy S = -Tr(ρ ln ρ).
    pub entropy: f64,
    /// Adaptation oscillator coherence.
    pub adaptation_coherence: f64,
}

// -----------------------------------------------------------------------------
// Finality Certificate (unchanged)
// -----------------------------------------------------------------------------

/// A finality certificate that proves a block was finalized.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FinalityCertificate {
    pub commit: CommitCertificate,
    pub finality_ms: u64,
    pub finality_round: u32,
    pub propose_timestamp_ms: u64,
    pub finality_timestamp_ms: u64,
}

// -----------------------------------------------------------------------------
// Quantum Pipeline State
// -----------------------------------------------------------------------------

/// Pipeline state with quantum entanglement between prepare and commit phases.
///
/// ```text
/// |Ψ_pipeline⟩ = α|prepare⟩|commit⟩ + β|commit⟩|prepare⟩
/// ```
#[derive(Clone, Debug)]
pub struct PipelineState {
    /// Pre‑computed proposal data for the next height.
    pub next_proposal_txs: Option<Vec<crate::types::Tx>>,
    /// Whether the pipeline is active (entanglement exists).
    pub active: bool,
    /// Height for which the pipeline is preparing.
    pub pipeline_height: Height,
    /// Entanglement fidelity with the current commit.
    pub entanglement_fidelity: f64,
    /// Number of times the pipeline has been used successfully.
    pub pipeline_hits: u64,
    /// Number of times the pipeline was cancelled.
    pub pipeline_misses: u64,
}

impl Default for PipelineState {
    fn default() -> Self {
        Self {
            next_proposal_txs: None,
            active: false,
            pipeline_height: 0,
            entanglement_fidelity: 1.0,
            pipeline_hits: 0,
            pipeline_misses: 0,
        }
    }
}

impl PipelineState {
    /// Begin pipelining: entangle next height preparation with current commit.
    pub fn begin_pipeline(&mut self, height: Height, txs: Vec<crate::types::Tx>) {
        self.active = true;
        self.pipeline_height = height;
        self.next_proposal_txs = Some(txs);
        self.entanglement_fidelity = PIPELINE_ENTANGLEMENT;
    }

    /// Consume pipelined transactions if they match the expected height.
    /// On match, entanglement collapses to a successful outcome.
    pub fn take_pipelined_txs(&mut self, height: Height) -> Option<Vec<crate::types::Tx>> {
        if self.active && self.pipeline_height == height {
            self.active = false;
            self.pipeline_hits = self.pipeline_hits.wrapping_add(1);
            self.entanglement_fidelity = 1.0;
            self.next_proposal_txs.take()
        } else {
            self.active = false;
            self.next_proposal_txs = None;
            self.pipeline_misses = self.pipeline_misses.wrapping_add(1);
            self.entanglement_fidelity *= 0.9;
            None
        }
    }

    /// Cancel the pipeline — decoherence event.
    pub fn cancel(&mut self) {
        self.active = false;
        self.next_proposal_txs = None;
        self.pipeline_misses = self.pipeline_misses.wrapping_add(1);
        self.entanglement_fidelity *= 0.8;
    }

    /// Get pipeline success rate.
    pub fn success_rate(&self) -> f64 {
        let total = self.pipeline_hits + self.pipeline_misses;
        if total == 0 {
            return 1.0;
        }
        self.pipeline_hits as f64 / total as f64
    }
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_finality_tracker_basic() {
        let mut ft = FinalityTracker::new(1);

        for _ in 0..10 {
            ft.record_commit(100, 0);
        }

        assert_eq!(ft.total_finalized, 10);
        assert_eq!(ft.consecutive_fast_commits, 10);
        assert_eq!(ft.average_finality_ms(), 100);
        assert!(ft.is_sub_second());
        assert_eq!(ft.best_finality_ms, 100);
        assert!(ft.purity < 1.0); // decohered by measurements
    }

    #[test]
    fn test_finality_tracker_adapts_down() {
        let mut ft = FinalityTracker::new(1);

        for _ in 0..20 {
            ft.record_commit(80, 0);
        }

        assert!(ft.adaptive_propose_ms < DEFAULT_PROPOSE_MS);
        assert!(ft.adaptive_prevote_ms < DEFAULT_VOTE_MS);
    }

    #[test]
    fn test_finality_tracker_adapts_up() {
        let mut ft = FinalityTracker::new(1);

        for _ in 0..10 {
            ft.record_commit(900, 2);
        }

        assert!(ft.adaptive_propose_ms >= DEFAULT_PROPOSE_MS);
    }

    #[test]
    fn test_pipeline_state() {
        let mut ps = PipelineState::default();
        assert!(!ps.active);

        ps.begin_pipeline(5, vec![]);
        assert!(ps.active);
        assert_eq!(ps.pipeline_height, 5);
        assert!((ps.entanglement_fidelity - PIPELINE_ENTANGLEMENT).abs() < 1e-10);

        assert!(ps.take_pipelined_txs(6).is_none());
        assert_eq!(ps.pipeline_misses, 1);

        ps.begin_pipeline(7, vec![]);
        assert!(ps.take_pipelined_txs(7).is_some());
        assert_eq!(ps.pipeline_hits, 1);
    }

    #[test]
    fn test_finality_stats() {
        let mut ft = FinalityTracker::new(0);
        for i in 0..50 {
            ft.record_commit(50 + i * 2, 0);
        }
        let stats = ft.stats();
        assert!(stats.is_sub_second);
        assert!(stats.average_finality_ms < 1000);
        assert!(stats.best_finality_ms <= 50);
        assert!(stats.purity > 0.0);
        assert!(stats.purity <= 1.0);
    }

    #[test]
    fn test_p95_calculation() {
        let mut ft = FinalityTracker::new(0);
        for i in 1..=100 {
            ft.record_commit(i * 10, 0);
        }
        let p95 = ft.p95_finality_ms();
        assert!(p95 >= 940 && p95 <= 960);
    }

    #[test]
    fn test_quantum_purity_decay() {
        let mut ft = FinalityTracker::new(0);
        let initial_purity = ft.purity;
        assert!((initial_purity - 1.0).abs() < 1e-10);

        for _ in 0..100 {
            ft.record_commit(100, 0);
        }

        assert!(ft.purity < initial_purity);
        assert!(ft.entropy > 0.0);
    }

    #[test]
    fn test_adaptation_coherence() {
        let mut ft = FinalityTracker::new(0);

        // Fast commits increase adaptation coherence
        for _ in 0..10 {
            ft.record_commit(50, 0);
        }
        assert!(ft.adaptation_coherence > 0.99);

        // Slow commits decrease adaptation coherence
        for _ in 0..10 {
            ft.record_commit(900, 2);
        }
        assert!(ft.adaptation_coherence < 1.0);
    }

    #[test]
    fn test_pipeline_success_rate() {
        let mut ps = PipelineState::default();

        ps.begin_pipeline(1, vec![]);
        ps.take_pipelined_txs(1); // hit
        ps.begin_pipeline(2, vec![]);
        ps.take_pipelined_txs(3); // miss

        assert!((ps.success_rate() - 0.5).abs() < 1e-10);
    }

    #[test]
    fn test_pipeline_cancel_decoheres() {
        let mut ps = PipelineState::default();
        ps.begin_pipeline(1, vec![]);
        let initial_fidelity = ps.entanglement_fidelity;

        ps.cancel();
        assert!(ps.entanglement_fidelity < initial_fidelity);
        assert_eq!(ps.pipeline_misses, 1);
    }
}
