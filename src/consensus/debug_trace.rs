//! STEP 4 — Quantum Consensus Debug Tracing.
//!
//! # Quantum Trace Model
//!
//! Each consensus event is a **projective measurement** on the consensus
//! Hilbert space ℋ_consensus = ℋ_height ⊗ ℋ_round ⊗ ℋ_proposal ⊗ ℋ_votes.
//! The trace is a sequence of measurement outcomes recording the
//! collapse of the consensus wavefunction at each step.
//!
//! # Hamiltonian for Consensus Evolution
//!
//! ```text
//! Ĥ_consensus = Ĥ_propose + Ĥ_prevote + Ĥ_precommit + Ĥ_commit + Ĥ_timeout
//!
//! Ĥ_propose   = Σ_h ω_h |proposal_h⟩⟨proposal_h|
//! Ĥ_prevote   = Σ_v g_v (|vote⟩⟨nil|_v + h.c.)
//! Ĥ_precommit = Σ_v κ_v |lock⟩⟨unlock|_v
//! Ĥ_commit    = E_commit |commit⟩⟨commit|
//! Ĥ_timeout   = Σ_t γ_t (n̂_t + ½)
//! ```
//!
//! # Quantum State Representation
//!
//! Each event is a quantum state |e_i⟩ in the event Hilbert space ℋ_event.
//! The trace is a tensor product of events:
//! ```text
//! |trace⟩ = |e_1⟩ ⊗ |e_2⟩ ⊗ ... ⊗ |e_N⟩
//! ```
//!
//! # Measurement Formalism
//!
//! - **NewHeight**: Ground state preparation |height⟩
//! - **NewRound**: Excitation to higher round state
//! - **Proposal**: Projective measurement in proposal basis
//! - **Prevote**: Born rule measurement P(vote) = Tr(ρ |vote⟩⟨vote|)
//! - **Precommit**: Locking measurement collapsing to |commit⟩ or |nil⟩
//! - **Commit**: Final projective measurement — consensus reached
//! - **Timeout**: Decoherence event from Lindblad operator L_timeout

use crate::types::{Hash32, Height};
use std::collections::BTreeMap;

// -----------------------------------------------------------------------------
// Quantum Constants
// -----------------------------------------------------------------------------

/// Reduced Planck constant (natural units).
const HBAR: f64 = 1.0;

/// Coherence decay per event recording.
const EVENT_DECOHERENCE_RATE: f64 = 0.00001;

/// Maximum events before ring buffer truncation (quantum memory bound).
const DEFAULT_MAX_EVENTS: usize = 10_000;

/// Default bucket size for quantum state tomography.
const TOMOGRAPHY_BUCKET_SIZE: u64 = 100;

// -----------------------------------------------------------------------------
// Quantum Consensus Event
// -----------------------------------------------------------------------------

/// A quantum consensus trace event — projective measurement outcome.
///
/// Each event is an element of a POVM {E_i} acting on ℋ_consensus,
/// with Born probability P(i) = Tr(ρ E_i).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConsensusEvent {
    /// New height started — ground state preparation |height⟩.
    NewHeight {
        height: Height,
        /// Quantum purity of the state at this height.
        #[cfg_attr(not(test), allow(dead_code))]
        purity: f64,
    },
    /// New round started — excitation to |round⟩.
    NewRound {
        height: Height,
        round: u32,
    },
    /// Proposal received/created — projective measurement in proposal basis.
    Proposal {
        height: Height,
        round: u32,
        proposer: String,
        block_hash: Hash32,
        tx_count: usize,
        /// Born probability of this proposal.
        born_probability: f64,
    },
    /// Prevote cast — measurement outcome |vote⟩ or |nil⟩.
    Prevote {
        height: Height,
        round: u32,
        validator: String,
        block_hash: Option<Hash32>,
        /// Entanglement fidelity with proposal.
        entanglement_fidelity: f64,
    },
    /// Precommit cast — locking measurement.
    Precommit {
        height: Height,
        round: u32,
        validator: String,
        block_hash: Option<Hash32>,
        /// Lock strength (fidelity with commit target).
        lock_fidelity: f64,
    },
    /// Block committed — final projective measurement.
    Commit {
        height: Height,
        round: u32,
        block_hash: Hash32,
        state_root: Hash32,
        tx_count: usize,
        gas_used: u64,
        /// Consensus fidelity (1.0 = perfect agreement).
        consensus_fidelity: f64,
    },
    /// Timeout occurred — Lindblad decoherence event.
    Timeout {
        height: Height,
        round: u32,
        phase: String,
        /// Decoherence strength.
        decoherence_strength: f64,
    },
    /// Round skip — quantum jump to higher round.
    RoundSkip {
        height: Height,
        from_round: u32,
        to_round: u32,
        reason: String,
        /// Jump probability (tunneling amplitude).
        jump_probability: f64,
    },
}

impl ConsensusEvent {
    /// Compute the quantum purity of this event.
    ///
    /// γ = Tr(ρ²) for the event's subspace.
    pub fn purity(&self) -> f64 {
        match self {
            Self::NewHeight { purity, .. } => *purity,
            Self::Proposal { born_probability, .. } => *born_probability,
            Self::Prevote { entanglement_fidelity, .. } => *entanglement_fidelity,
            Self::Precommit { lock_fidelity, .. } => *lock_fidelity,
            Self::Commit { consensus_fidelity, .. } => *consensus_fidelity,
            Self::Timeout { decoherence_strength, .. } => 1.0 - *decoherence_strength,
            Self::RoundSkip { jump_probability, .. } => *jump_probability,
            Self::NewRound { .. } => 1.0,
        }
    }
}

impl std::fmt::Display for ConsensusEvent {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NewHeight { height, purity } => {
                write!(
                    f,
                    "[CONSENSUS] NEW_HEIGHT height={height} γ={purity:.4}"
                )
            }
            Self::NewRound { height, round } => {
                write!(f, "[CONSENSUS] NEW_ROUND height={height} round={round}")
            }
            Self::Proposal {
                height,
                round,
                proposer,
                block_hash,
                tx_count,
                born_probability,
            } => {
                write!(
                    f,
                    "[CONSENSUS] PROPOSAL height={height} round={round} proposer={proposer} hash=0x{} txs={tx_count} P={born_probability:.4}",
                    hex::encode(&block_hash.0[..8])
                )
            }
            Self::Prevote {
                height,
                round,
                validator,
                block_hash,
                entanglement_fidelity,
            } => {
                let vote = block_hash
                    .as_ref()
                    .map(|h| format!("0x{}", hex::encode(&h.0[..8])))
                    .unwrap_or_else(|| "NIL".into());
                write!(
                    f,
                    "[CONSENSUS] PREVOTE height={height} round={round} validator={validator} vote={vote} F={entanglement_fidelity:.4}"
                )
            }
            Self::Precommit {
                height,
                round,
                validator,
                block_hash,
                lock_fidelity,
            } => {
                let vote = block_hash
                    .as_ref()
                    .map(|h| format!("0x{}", hex::encode(&h.0[..8])))
                    .unwrap_or_else(|| "NIL".into());
                write!(
                    f,
                    "[CONSENSUS] PRECOMMIT height={height} round={round} validator={validator} vote={vote} L={lock_fidelity:.4}"
                )
            }
            Self::Commit {
                height,
                round,
                block_hash,
                state_root,
                tx_count,
                gas_used,
                consensus_fidelity,
            } => {
                write!(
                    f,
                    "[CONSENSUS] COMMIT height={height} round={round} hash=0x{} root=0x{} txs={tx_count} gas={gas_used} F_c={consensus_fidelity:.4}",
                    hex::encode(&block_hash.0[..8]),
                    hex::encode(&state_root.0[..8])
                )
            }
            Self::Timeout {
                height,
                round,
                phase,
                decoherence_strength,
            } => {
                write!(
                    f,
                    "[CONSENSUS] TIMEOUT height={height} round={round} phase={phase} γ_loss={decoherence_strength:.4}"
                )
            }
            Self::RoundSkip {
                height,
                from_round,
                to_round,
                reason,
                jump_probability,
            } => {
                write!(
                    f,
                    "[CONSENSUS] ROUND_SKIP height={height} from={from_round} to={to_round} reason={reason} P_jump={jump_probability:.4}"
                )
            }
        }
    }
}

// -----------------------------------------------------------------------------
// Quantum Consensus Tracer
// -----------------------------------------------------------------------------

/// Quantum consensus debug tracer that collects structured events.
///
/// The tracer maintains a quantum state |trace⟩ = ⊗ |e_i⟩ of all
/// consensus events, bounded by `max_events` (quantum memory limit).
///
/// # Usage
/// ```text
/// [CONSENSUS] NEW_HEIGHT height=100 γ=0.9999
/// [CONSENSUS] NEW_ROUND height=100 round=0
/// [CONSENSUS] PROPOSAL height=100 round=0 proposer=val2 hash=0xabcd... txs=5 P=0.98
/// [CONSENSUS] PREVOTE height=100 round=0 validator=val2 vote=0xabcd... F=0.99
/// [CONSENSUS] PRECOMMIT height=100 round=0 validator=val2 vote=0xabcd... L=1.00
/// [CONSENSUS] COMMIT height=100 round=0 hash=0xabcd... root=0x1234... txs=5 gas=21000 F_c=1.00
/// ```
#[derive(Debug)]
pub struct ConsensusTracer {
    /// Recorded events (quantum state history).
    events: Vec<ConsensusEvent>,
    /// Maximum number of events (quantum memory bound).
    max_events: usize,
    /// Whether tracing is enabled.
    enabled: bool,
    /// Quantum coherence of the trace.
    coherence: f64,
    /// Total events ever recorded (including evicted).
    total_events_recorded: u64,
    /// Total events evicted from ring buffer.
    total_events_evicted: u64,
}

impl ConsensusTracer {
    /// Create a new quantum tracer.
    ///
    /// Initializes the trace in the vacuum state |∅⟩.
    pub fn new(enabled: bool, max_events: usize) -> Self {
        Self {
            events: Vec::with_capacity(max_events.min(DEFAULT_MAX_EVENTS)),
            max_events: max_events.min(DEFAULT_MAX_EVENTS),
            enabled,
            coherence: 1.0,
            total_events_recorded: 0,
            total_events_evicted: 0,
        }
    }

    /// Record a consensus event — apply creation operator a†.
    ///
    /// ```text
    /// a† |trace⟩ → |trace ⊗ event⟩
    /// ```
    pub fn record(&mut self, event: ConsensusEvent) {
        if !self.enabled {
            return;
        }

        // Ring buffer: if full, evict oldest (annihilation operator a)
        if self.events.len() >= self.max_events {
            self.events.remove(0);
            self.total_events_evicted += 1;
        }

        self.events.push(event);
        self.total_events_recorded += 1;

        // Apply decoherence from measurement
        self.coherence = (self.coherence * (1.0 - EVENT_DECOHERENCE_RATE))
            .max(0.0);
    }

    /// Record a new height event — ground state preparation.
    pub fn trace_new_height(&mut self, height: Height) {
        let purity = self.coherence;
        self.record(ConsensusEvent::NewHeight { height, purity });
    }

    /// Record a new round event — excitation.
    pub fn trace_new_round(&mut self, height: Height, round: u32) {
        self.record(ConsensusEvent::NewRound { height, round });
    }

    /// Record a proposal event — projective measurement.
    pub fn trace_proposal(
        &mut self,
        height: Height,
        round: u32,
        proposer: &str,
        block_hash: Hash32,
        tx_count: usize,
    ) {
        let born_probability = self.coherence;
        self.record(ConsensusEvent::Proposal {
            height,
            round,
            proposer: proposer.to_string(),
            block_hash,
            tx_count,
            born_probability,
        });
    }

    /// Record a prevote event — Born rule outcome.
    pub fn trace_prevote(
        &mut self,
        height: Height,
        round: u32,
        validator: &str,
        block_hash: Option<Hash32>,
    ) {
        let entanglement_fidelity = self.coherence;
        self.record(ConsensusEvent::Prevote {
            height,
            round,
            validator: validator.to_string(),
            block_hash,
            entanglement_fidelity,
        });
    }

    /// Record a precommit event — locking measurement.
    pub fn trace_precommit(
        &mut self,
        height: Height,
        round: u32,
        validator: &str,
        block_hash: Option<Hash32>,
    ) {
        let lock_fidelity = self.coherence;
        self.record(ConsensusEvent::Precommit {
            height,
            round,
            validator: validator.to_string(),
            block_hash,
            lock_fidelity,
        });
    }

    /// Record a commit event — final projective measurement.
    pub fn trace_commit(
        &mut self,
        height: Height,
        round: u32,
        block_hash: Hash32,
        state_root: Hash32,
        tx_count: usize,
        gas_used: u64,
    ) {
        let consensus_fidelity = self.coherence;
        self.record(ConsensusEvent::Commit {
            height,
            round,
            block_hash,
            state_root,
            tx_count,
            gas_used,
            consensus_fidelity,
        });
    }

    /// Record a timeout event — Lindblad decoherence.
    pub fn trace_timeout(&mut self, height: Height, round: u32, phase: &str) {
        let decoherence_strength = 1.0 - self.coherence;
        self.record(ConsensusEvent::Timeout {
            height,
            round,
            phase: phase.to_string(),
            decoherence_strength,
        });
    }

    /// Record a round skip — quantum jump.
    pub fn trace_round_skip(&mut self, height: Height, from: u32, to: u32, reason: &str) {
        let jump_probability = 1.0 / (to - from).max(1) as f64;
        self.record(ConsensusEvent::RoundSkip {
            height,
            from_round: from,
            to_round: to,
            reason: reason.to_string(),
            jump_probability,
        });
    }

    /// Get all recorded events.
    pub fn events(&self) -> &[ConsensusEvent] {
        &self.events
    }

    /// Get events for a specific height.
    pub fn events_at_height(&self, height: Height) -> Vec<&ConsensusEvent> {
        self.events
            .iter()
            .filter(|e| event_height(e) == Some(height))
            .collect()
    }

    /// Get the latest commit event.
    pub fn latest_commit(&self) -> Option<&ConsensusEvent> {
        self.events
            .iter()
            .rev()
            .find(|e| matches!(e, ConsensusEvent::Commit { .. }))
    }

    /// Get quantum state tomography for a height range.
    ///
    /// Returns statistics with average coherence and fidelity metrics.
    pub fn stats(&self, from: Height, to: Height) -> QuantumConsensusStats {
        let relevant: Vec<&ConsensusEvent> = self
            .events
            .iter()
            .filter(|e| {
                event_height(e)
                    .map(|h| h >= from && h <= to)
                    .unwrap_or(false)
            })
            .collect();

        let proposals = relevant
            .iter()
            .filter(|e| matches!(e, ConsensusEvent::Proposal { .. }))
            .count();
        let prevotes = relevant
            .iter()
            .filter(|e| matches!(e, ConsensusEvent::Prevote { .. }))
            .count();
        let precommits = relevant
            .iter()
            .filter(|e| matches!(e, ConsensusEvent::Precommit { .. }))
            .count();
        let commits = relevant
            .iter()
            .filter(|e| matches!(e, ConsensusEvent::Commit { .. }))
            .count();
        let timeouts = relevant
            .iter()
            .filter(|e| matches!(e, ConsensusEvent::Timeout { .. }))
            .count();
        let round_skips = relevant
            .iter()
            .filter(|e| matches!(e, ConsensusEvent::RoundSkip { .. }))
            .count();

        // Compute average coherence from events
        let total_purity: f64 = relevant.iter().map(|e| e.purity()).sum();
        let avg_coherence = if relevant.is_empty() {
            1.0
        } else {
            total_purity / relevant.len() as f64
        };

        QuantumConsensusStats {
            from,
            to,
            proposals,
            prevotes,
            precommits,
            commits,
            timeouts,
            round_skips,
            avg_coherence,
            total_events: relevant.len(),
        }
    }

    /// Clear all events — reset to vacuum state |∅⟩.
    pub fn clear(&mut self) {
        self.events.clear();
        self.coherence = 1.0;
    }

    /// Check if tracing is enabled.
    pub fn is_enabled(&self) -> bool {
        self.enabled
    }

    /// Get current tracer coherence.
    pub fn coherence(&self) -> f64 {
        self.coherence
    }

    /// Get total events recorded (including evicted).
    pub fn total_recorded(&self) -> u64 {
        self.total_events_recorded
    }

    /// Get total events evicted.
    pub fn total_evicted(&self) -> u64 {
        self.total_events_evicted
    }
}

// -----------------------------------------------------------------------------
// Helper Functions
// -----------------------------------------------------------------------------

/// Extract height from a consensus event.
fn event_height(event: &ConsensusEvent) -> Option<Height> {
    match event {
        ConsensusEvent::NewHeight { height, .. } => Some(*height),
        ConsensusEvent::NewRound { height, .. } => Some(*height),
        ConsensusEvent::Proposal { height, .. } => Some(*height),
        ConsensusEvent::Prevote { height, .. } => Some(*height),
        ConsensusEvent::Precommit { height, .. } => Some(*height),
        ConsensusEvent::Commit { height, .. } => Some(*height),
        ConsensusEvent::Timeout { height, .. } => Some(*height),
        ConsensusEvent::RoundSkip { height, .. } => Some(*height),
    }
}

// -----------------------------------------------------------------------------
// Quantum Consensus Statistics
// -----------------------------------------------------------------------------

/// Aggregated quantum consensus statistics.
///
/// Includes both classical counts and quantum metrics
/// (average coherence, fidelity).
#[derive(Debug, Clone)]
pub struct QuantumConsensusStats {
    pub from: Height,
    pub to: Height,
    pub proposals: usize,
    pub prevotes: usize,
    pub precommits: usize,
    pub commits: usize,
    pub timeouts: usize,
    pub round_skips: usize,
    /// Average quantum coherence across all events.
    pub avg_coherence: f64,
    /// Total events analyzed.
    pub total_events: usize,
}

impl std::fmt::Display for QuantumConsensusStats {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Consensus Stats [{:.?}..{:.?}]: proposals={} prevotes={} precommits={} commits={} timeouts={} round_skips={} γ_avg={:.4} events={}",
            self.from,
            self.to,
            self.proposals,
            self.prevotes,
            self.precommits,
            self.commits,
            self.timeouts,
            self.round_skips,
            self.avg_coherence,
            self.total_events,
        )
    }
}

// -----------------------------------------------------------------------------
// STEP 5: Quantum State Root Log
// -----------------------------------------------------------------------------

/// Per-block state root log entry with quantum fingerprint.
#[derive(Debug, Clone)]
pub struct StateRootLogEntry {
    pub height: Height,
    pub state_root: Hash32,
    pub timestamp: u64,
    /// Quantum fidelity of the state root.
    pub fidelity: f64,
}

impl std::fmt::Display for StateRootLogEntry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "height={} root=0x{} F={:.4}",
            self.height,
            hex::encode(self.state_root.0),
            self.fidelity
        )
    }
}

/// Quantum state root logger — maintains a log of (height, state_root)
/// for every committed block with quantum fidelity tracking.
#[derive(Debug)]
pub struct StateRootLog {
    entries: BTreeMap<Height, StateRootLogEntry>,
    enabled: bool,
    /// Quantum coherence of the log.
    coherence: f64,
}

impl StateRootLog {
    /// Create a new state root log.
    pub fn new(enabled: bool) -> Self {
        Self {
            entries: BTreeMap::new(),
            enabled,
            coherence: 1.0,
        }
    }

    /// Log a state root for a committed block.
    ///
    /// Applies minor decoherence from the logging operation.
    pub fn log(&mut self, height: Height, state_root: Hash32, timestamp: u64) {
        if !self.enabled {
            return;
        }
        let fidelity = self.coherence;
        self.entries.insert(
            height,
            StateRootLogEntry {
                height,
                state_root,
                timestamp,
                fidelity,
            },
        );
        // Minor decoherence from storage operation
        self.coherence = (self.coherence * 0.99999).max(0.0);
    }

    /// Get the state root at a specific height.
    pub fn get(&self, height: Height) -> Option<&StateRootLogEntry> {
        self.entries.get(&height)
    }

    /// Get all entries as a BTreeMap of height -> Hash32 (for cross-node comparison).
    pub fn roots(&self) -> BTreeMap<Height, Hash32> {
        self.entries
            .iter()
            .map(|(&h, e)| (h, e.state_root))
            .collect()
    }

    /// Get the latest logged height.
    pub fn latest_height(&self) -> Option<Height> {
        self.entries.keys().next_back().copied()
    }

    /// Get total entries.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Check if empty.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Get current log coherence.
    pub fn coherence(&self) -> f64 {
        self.coherence
    }

    /// Export log as text (for `iona compare` tool).
    pub fn export_text(&self) -> String {
        let mut out = String::new();
        for entry in self.entries.values() {
            out.push_str(&format!("{entry}\n"));
        }
        out
    }
}

// ─── Tests ──────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── Quantum Tracer Tests ────────────────────────────────────────────
    #[test]
    fn test_tracer_basic_flow() {
        let mut tracer = ConsensusTracer::new(true, 1000);

        tracer.trace_new_height(100);
        tracer.trace_new_round(100, 0);
        tracer.trace_proposal(100, 0, "val2", Hash32([0xAB; 32]), 5);
        tracer.trace_prevote(100, 0, "val2", Some(Hash32([0xAB; 32])));
        tracer.trace_prevote(100, 0, "val3", Some(Hash32([0xAB; 32])));
        tracer.trace_precommit(100, 0, "val2", Some(Hash32([0xAB; 32])));
        tracer.trace_precommit(100, 0, "val3", Some(Hash32([0xAB; 32])));
        tracer.trace_commit(
            100,
            0,
            Hash32([0xAB; 32]),
            Hash32([0xCD; 32]),
            5,
            21000,
        );

        assert_eq!(tracer.events().len(), 8);
        assert!(tracer.coherence() < 1.0); // decoherence from recordings
    }

    #[test]
    fn test_tracer_disabled() {
        let mut tracer = ConsensusTracer::new(false, 100);
        tracer.trace_new_height(1);
        assert!(tracer.events().is_empty());
        assert_eq!(tracer.total_recorded(), 0);
    }

    #[test]
    fn test_tracer_ring_buffer() {
        let mut tracer = ConsensusTracer::new(true, 3);
        tracer.trace_new_height(1);
        tracer.trace_new_height(2);
        tracer.trace_new_height(3);
        tracer.trace_new_height(4); // Should evict height=1.

        assert_eq!(tracer.events().len(), 3);
        assert_eq!(tracer.total_evicted(), 1);
        assert_eq!(
            tracer.events()[0],
            ConsensusEvent::NewHeight {
                height: 2,
                purity: tracer.events()[0].purity()
            }
        );
    }

    #[test]
    fn test_events_at_height() {
        let mut tracer = ConsensusTracer::new(true, 100);
        tracer.trace_new_height(100);
        tracer.trace_proposal(100, 0, "val2", Hash32([0; 32]), 0);
        tracer.trace_new_height(101);

        let at_100 = tracer.events_at_height(100);
        assert_eq!(at_100.len(), 2);

        let at_101 = tracer.events_at_height(101);
        assert_eq!(at_101.len(), 1);
    }

    #[test]
    fn test_latest_commit() {
        let mut tracer = ConsensusTracer::new(true, 100);
        tracer.trace_commit(1, 0, Hash32([1; 32]), Hash32([2; 32]), 0, 0);
        tracer.trace_commit(2, 0, Hash32([3; 32]), Hash32([4; 32]), 1, 100);
        tracer.trace_new_height(3);

        let commit = tracer.latest_commit().unwrap();
        match commit {
            ConsensusEvent::Commit { height, .. } => assert_eq!(*height, 2),
            _ => panic!("expected Commit"),
        }
    }

    #[test]
    fn test_quantum_consensus_stats() {
        let mut tracer = ConsensusTracer::new(true, 100);
        tracer.trace_new_height(1);
        tracer.trace_proposal(1, 0, "v", Hash32([0; 32]), 0);
        tracer.trace_prevote(1, 0, "v1", None);
        tracer.trace_prevote(1, 0, "v2", Some(Hash32([0; 32])));
        tracer.trace_precommit(1, 0, "v1", Some(Hash32([0; 32])));
        tracer.trace_commit(1, 0, Hash32([0; 32]), Hash32([0; 32]), 0, 0);
        tracer.trace_timeout(1, 0, "propose");

        let stats = tracer.stats(1, 1);
        assert_eq!(stats.proposals, 1);
        assert_eq!(stats.prevotes, 2);
        assert_eq!(stats.precommits, 1);
        assert_eq!(stats.commits, 1);
        assert_eq!(stats.timeouts, 1);
        assert!(stats.avg_coherence > 0.0);
        assert!(stats.avg_coherence <= 1.0);
    }

    #[test]
    fn test_consensus_stats_display() {
        let stats = QuantumConsensusStats {
            from: 1,
            to: 100,
            proposals: 100,
            prevotes: 300,
            precommits: 300,
            commits: 100,
            timeouts: 2,
            round_skips: 1,
            avg_coherence: 0.95,
            total_events: 803,
        };
        let s = format!("{stats}");
        assert!(s.contains("proposals=100"));
        assert!(s.contains("commits=100"));
        assert!(s.contains("γ_avg=0.9500"));
    }

    #[test]
    fn test_event_display_quantum() {
        let events = vec![
            ConsensusEvent::NewHeight {
                height: 42,
                purity: 0.99,
            },
            ConsensusEvent::Proposal {
                height: 42,
                round: 0,
                proposer: "val2".into(),
                block_hash: Hash32([0xAB; 32]),
                tx_count: 5,
                born_probability: 0.98,
            },
            ConsensusEvent::Prevote {
                height: 42,
                round: 0,
                validator: "val2".into(),
                block_hash: Some(Hash32([0xAB; 32])),
                entanglement_fidelity: 0.99,
            },
            ConsensusEvent::Precommit {
                height: 42,
                round: 0,
                validator: "val2".into(),
                block_hash: Some(Hash32([0xAB; 32])),
                lock_fidelity: 1.0,
            },
            ConsensusEvent::Commit {
                height: 42,
                round: 0,
                block_hash: Hash32([0xAB; 32]),
                state_root: Hash32([0xCD; 32]),
                tx_count: 5,
                gas_used: 21000,
                consensus_fidelity: 1.0,
            },
            ConsensusEvent::Timeout {
                height: 42,
                round: 0,
                phase: "propose".into(),
                decoherence_strength: 0.01,
            },
        ];

        for event in &events {
            let s = format!("{event}");
            assert!(s.starts_with("[CONSENSUS]"), "event display: {s}");
        }

        // Check specific quantum fields in display
        let new_height_str = format!("{}", events[0]);
        assert!(new_height_str.contains("γ=0.99"));

        let commit_str = format!("{}", events[4]);
        assert!(commit_str.contains("F_c=1.00"));
    }

    #[test]
    fn test_tracer_clear() {
        let mut tracer = ConsensusTracer::new(true, 100);
        tracer.trace_new_height(1);
        assert_eq!(tracer.events().len(), 1);
        tracer.clear();
        assert!(tracer.events().is_empty());
        assert!((tracer.coherence() - 1.0).abs() < 1e-10);
    }

    #[test]
    fn test_tracer_timeout_and_round_skip() {
        let mut tracer = ConsensusTracer::new(true, 100);
        tracer.trace_timeout(1, 0, "propose");
        tracer.trace_round_skip(1, 0, 1, "proposal timeout");

        assert_eq!(tracer.events().len(), 2);
        match &tracer.events()[0] {
            ConsensusEvent::Timeout {
                decoherence_strength,
                ..
            } => assert!(*decoherence_strength >= 0.0),
            _ => panic!("expected Timeout"),
        }
    }

    // ── State Root Log Tests ────────────────────────────────────────────
    #[test]
    fn test_state_root_log() {
        let mut log = StateRootLog::new(true);

        log.log(1, Hash32([0x01; 32]), 1000);
        log.log(2, Hash32([0x02; 32]), 2000);
        log.log(3, Hash32([0x03; 32]), 3000);

        assert_eq!(log.len(), 3);
        assert_eq!(log.latest_height(), Some(3));

        let entry = log.get(2).unwrap();
        assert_eq!(entry.height, 2);
        assert_eq!(entry.state_root, Hash32([0x02; 32]));
        assert!(entry.fidelity > 0.0);
    }

    #[test]
    fn test_state_root_log_disabled() {
        let mut log = StateRootLog::new(false);
        log.log(1, Hash32([0x01; 32]), 1000);
        assert!(log.is_empty());
    }

    #[test]
    fn test_state_root_log_export() {
        let mut log = StateRootLog::new(true);
        log.log(1, Hash32([0xAA; 32]), 1000);
        log.log(2, Hash32([0xBB; 32]), 2000);

        let text = log.export_text();
        assert!(text.contains("height=1"));
        assert!(text.contains("height=2"));
        assert!(text.contains("root=0x"));
        assert!(text.contains("F="));
    }

    #[test]
    fn test_state_root_log_coherence() {
        let mut log = StateRootLog::new(true);
        let initial = log.coherence();
        log.log(1, Hash32([0x01; 32]), 1000);
        log.log(2, Hash32([0x02; 32]), 2000);
        assert!(log.coherence() < initial);
    }

    #[test]
    fn test_event_purity_method() {
        let event = ConsensusEvent::NewHeight {
            height: 1,
            purity: 0.95,
        };
        assert!((event.purity() - 0.95).abs() < 1e-10);

        let event = ConsensusEvent::Timeout {
            height: 1,
            round: 0,
            phase: "propose".into(),
            decoherence_strength: 0.03,
        };
        assert!((event.purity() - 0.97).abs() < 1e-10);
    }

    #[test]
    fn test_nil_prevote_display() {
        let event = ConsensusEvent::Prevote {
            height: 1,
            round: 0,
            validator: "val2".into(),
            block_hash: None,
            entanglement_fidelity: 0.5,
        };
        let s = format!("{event}");
        assert!(s.contains("NIL"));
        assert!(s.contains("F=0.50"));
    }
}
