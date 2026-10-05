//! Consensus diagnostic module for IONA v28 — Production‑Grade.
//!
//! When consensus stalls, this module provides a clear, single‑line answer
//! to "why no commit?" instead of requiring you to read multiple logs.
//!
//! # Features
//! - Multi‑reason stall detection (proposal, votes, connectivity, rounds).
//! - Quorum‑aware diagnostics using `QuorumCalculator` with stake‑weighted power.
//! - Human‑readable summaries for logging and monitoring.
//! - Configurable diagnostic parameters with validated ranges.
//! - Statistics tracking for operational insights.
//! - Rate‑limited diagnostics with a **bounded** rate‑limiter map (no leak).
//! - Structured `tracing` at debug level for the diagnostic path.
//!
//! # Example output
//! ```text
//! NO_COMMIT height=42 round=0: waiting_proposal(from=val1, 150/300ms),
//!   low_connectivity(connected=2/4 need=3)
//! ```
//!
//! # Concurrency
//!
//! [`DiagnosticCollector`] is `Clone` and safe to share across threads: all
//! internal state is behind [`parking_lot::Mutex`], which does not poison on
//! panic. The standalone [`diagnose_with_stake`] function is pure and
//! allocation‑bounded.
//!
//! # Rate limiting and memory
//!
//! The collector keeps a bounded rate‑limiter map (capacity
//! [`MAX_RATE_LIMIT_ENTRIES`]) so a long‑running node with monotonic heights
//! cannot leak memory. Oldest `(height, round)` entries are evicted on insert.

use crate::consensus::engine::{ConsensusState, Step};
use crate::consensus::quorum_diag::QuorumCalculator;
use crate::consensus::validator_set::ValidatorSet;
use crate::crypto::PublicKeyBytes;
use crate::slashing::StakeLedger;
use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap, HashSet, VecDeque};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tracing::debug;

// -----------------------------------------------------------------------------
// Constants
// -----------------------------------------------------------------------------

/// Prefix length for hex‑shortened public keys in logs.
const HEX_SHORT_LEN: usize = 8;

/// Default maximum number of stall reasons to include.
const DEFAULT_MAX_REASONS: usize = 5;

/// Default maximum rounds before flagging round advancement.
const DEFAULT_MAX_ROUNDS: u32 = 10;

/// Default minimum interval between diagnostics for the same height/round (ms).
const DEFAULT_MIN_DIAG_INTERVAL_MS: u64 = 5000;

/// Default maximum number of historical diagnostics to keep.
const DEFAULT_MAX_HISTORY: usize = 100;

/// Hard cap for `max_history` (memory guard).
const MAX_ALLOWED_HISTORY: usize = 100_000;

/// Hard cap for `max_reasons` (sanity guard).
const MAX_ALLOWED_REASONS: usize = 64;

/// Bound on the rate‑limiter map size. Prevents unbounded growth on a node
/// that advances many heights/rounds.
const MAX_RATE_LIMIT_ENTRIES: usize = 4096;

// -----------------------------------------------------------------------------
// Configuration
// -----------------------------------------------------------------------------

/// Configuration for the diagnostic module.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DiagnosticConfig {
    /// Maximum number of stall reasons to include in the summary.
    pub max_reasons: usize,
    /// Maximum rounds before flagging round advancement as a stall reason.
    pub max_rounds: u32,
    /// Whether to include detailed validator lists in stall reasons.
    pub include_validator_details: bool,
    /// Whether to track statistics.
    pub enable_statistics: bool,
    /// Minimum interval between diagnostics for the same height/round (ms).
    pub min_diag_interval_ms: u64,
    /// Maximum number of historical diagnostics to keep in memory.
    pub max_history: usize,
    /// Whether the caller should emit Prometheus metrics.
    ///
    /// This module does **not** emit metrics itself; it is a signal flag for
    /// the outer metrics layer. Kept in the config for forward compatibility.
    pub enable_metrics: bool,
}

impl Default for DiagnosticConfig {
    fn default() -> Self {
        Self {
            max_reasons: DEFAULT_MAX_REASONS,
            max_rounds: DEFAULT_MAX_ROUNDS,
            include_validator_details: true,
            enable_statistics: true,
            min_diag_interval_ms: DEFAULT_MIN_DIAG_INTERVAL_MS,
            max_history: DEFAULT_MAX_HISTORY,
            enable_metrics: false,
        }
    }
}

impl DiagnosticConfig {
    /// Validate the configuration.
    ///
    /// Returns `Err(String)` with a human‑readable reason. Callers should
    /// surface this to operators (e.g. via `anyhow`/`thiserror`) rather than
    /// panicking.
    pub fn validate(&self) -> Result<(), String> {
        if self.max_reasons == 0 {
            return Err("max_reasons must be > 0".into());
        }
        if self.max_reasons > MAX_ALLOWED_REASONS {
            return Err(format!(
                "max_reasons must be <= {} (got {})",
                MAX_ALLOWED_REASONS, self.max_reasons
            ));
        }
        if self.max_rounds == 0 {
            return Err("max_rounds must be > 0".into());
        }
        if self.min_diag_interval_ms == 0 {
            return Err("min_diag_interval_ms must be > 0".into());
        }
        if self.max_history == 0 {
            return Err("max_history must be > 0".into());
        }
        if self.max_history > MAX_ALLOWED_HISTORY {
            return Err(format!(
                "max_history must be <= {} (got {})",
                MAX_ALLOWED_HISTORY, self.max_history
            ));
        }
        Ok(())
    }
}

// -----------------------------------------------------------------------------
// Statistics
// -----------------------------------------------------------------------------

/// Statistics collected during diagnostic operations.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct DiagnosticStats {
    /// Total number of diagnostic runs.
    pub total_diagnostics: u64,
    /// Number of times consensus was healthy.
    pub healthy_count: u64,
    /// Number of times consensus was stalled.
    pub stalled_count: u64,
    /// Breakdown of stall reasons encountered.
    pub reason_counts: HashMap<String, u64>,
    /// Average number of reasons per stalled diagnostic.
    pub avg_reasons_per_stall: f64,
}

impl DiagnosticStats {
    /// Record a diagnostic result.
    ///
    /// The healthy/stalled classification uses
    /// [`ConsensusDiagnostic::is_healthy`], **not** whether
    /// [`ConsensusDiagnostic::stall_reasons`] is empty. This matters for
    /// `AlreadyCommitted` (a non‑stalled event that still carries one reason
    /// for observability).
    pub fn record(&mut self, diag: &ConsensusDiagnostic) {
        self.total_diagnostics = self.total_diagnostics.saturating_add(1);
        if diag.is_healthy {
            self.healthy_count = self.healthy_count.saturating_add(1);
        } else {
            self.stalled_count = self.stalled_count.saturating_add(1);
            let n = self.stalled_count as f64;
            let reasons = diag.stall_reasons.len() as f64;
            // Running mean, guarded against the (n == 0) branch.
            self.avg_reasons_per_stall =
                (self.avg_reasons_per_stall * (n - 1.0) + reasons) / n;
        }
        for reason in &diag.stall_reasons {
            let key = reason_type_name(reason);
            *self.reason_counts.entry(key).or_insert(0) += 1;
        }
    }

    /// Reset all statistics.
    pub fn reset(&mut self) {
        *self = Self::default();
    }
}

/// Return a stable string name for a stall reason variant.
///
/// The name is a stable identifier suitable for Prometheus labels and logs —
/// do not reorder or rename without a migration.
pub fn reason_type_name(reason: &StallReason) -> String {
    match reason {
        StallReason::WaitingForProposal { .. } => "waiting_for_proposal",
        StallReason::MissingBlock { .. } => "missing_block",
        StallReason::InsufficientPrevotes { .. } => "insufficient_prevotes",
        StallReason::InsufficientPrecommits { .. } => "insufficient_precommits",
        StallReason::NoConnectedValidators { .. } => "no_connected_validators",
        StallReason::InsufficientConnectedValidators { .. } => {
            "insufficient_connected_validators"
        }
        StallReason::AlreadyCommitted { .. } => "already_committed",
        StallReason::RoundAdvancing { .. } => "round_advancing",
        StallReason::NoProposalInRound { .. } => "no_proposal_in_round",
        StallReason::ProposerNotConnected { .. } => "proposer_not_connected",
        StallReason::ProposerMismatch { .. } => "proposer_mismatch",
        StallReason::ProposalBlockHashMismatch { .. } => {
            "proposal_block_hash_mismatch"
        }
        StallReason::InvalidProposalSignature { .. } => "invalid_proposal_signature",
        StallReason::QuorumNotReached { .. } => "quorum_not_reached",
        StallReason::NotProposer { .. } => "not_proposer",
        StallReason::AlreadyVoted { .. } => "already_voted",
        StallReason::TimedOut { .. } => "timed_out",
        StallReason::StaleMessage { .. } => "stale_message",
        StallReason::DuplicateVote { .. } => "duplicate_vote",
    }
    .into()
}

// -----------------------------------------------------------------------------
// Stall reasons (extended)
// -----------------------------------------------------------------------------

/// Possible reasons for consensus not committing.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "reason")]
pub enum StallReason {
    /// Waiting for proposal from the designated proposer.
    WaitingForProposal {
        proposer: String,
        elapsed_ms: u64,
        timeout_ms: u64,
    },
    /// Proposal received but block not yet available.
    MissingBlock { block_id: String },
    /// Not enough prevotes to proceed.
    InsufficientPrevotes {
        have: u64,
        need: u64,
        #[serde(skip_serializing_if = "Vec::is_empty", default)]
        voted: Vec<String>,
        #[serde(skip_serializing_if = "Vec::is_empty", default)]
        missing: Vec<String>,
    },
    /// Not enough precommits to commit.
    InsufficientPrecommits {
        have: u64,
        need: u64,
        #[serde(skip_serializing_if = "Vec::is_empty", default)]
        voted: Vec<String>,
        #[serde(skip_serializing_if = "Vec::is_empty", default)]
        missing: Vec<String>,
    },
    /// No connected validators (P2P issue).
    NoConnectedValidators { total_validators: usize },
    /// Too few connected validators for quorum.
    InsufficientConnectedValidators {
        connected: usize,
        total: usize,
        needed: usize,
    },
    /// Already committed at this height. Not a stall — carried for
    /// observability. `ConsensusDiagnostic::is_healthy` will be `true`.
    AlreadyCommitted { height: u64 },
    /// Round is advancing (timeout‑driven).
    RoundAdvancing { current_round: u32, max_rounds: u32 },
    /// No proposal for this round (missing block or message).
    NoProposalInRound { round: u32 },
    /// Designated proposer is not connected.
    ProposerNotConnected { proposer: String },
    /// The received proposal has a different proposer than expected.
    ProposerMismatch { expected: String, actual: String },
    /// The block hash in the proposal does not match the block.
    ProposalBlockHashMismatch { expected: String, actual: String },
    /// Invalid signature on the proposal.
    InvalidProposalSignature { proposer: String, reason: String },
    /// General quorum not reached (aggregate power).
    QuorumNotReached { have: u64, need: u64 },
    /// This node is not the proposer for the round.
    NotProposer { proposer: String },
    /// Already voted in this round (duplicate attempt).
    AlreadyVoted { vote_type: String },
    /// Step timeout reached.
    TimedOut {
        step: String,
        elapsed_ms: u64,
        timeout_ms: u64,
    },
    /// Stale message (height/round mismatch).
    StaleMessage { reason: String },
    /// Duplicate vote from the same validator.
    DuplicateVote { validator: String, vote_type: String },
}

// -----------------------------------------------------------------------------
// Diagnostic snapshot
// -----------------------------------------------------------------------------

/// Full diagnostic snapshot.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ConsensusDiagnostic {
    pub height: u64,
    pub round: u32,
    pub step: String,
    pub stall_reasons: Vec<StallReason>,
    /// One‑line summary for quick logging.
    pub summary: String,
    /// Whether consensus is healthy (no stall reasons *that indicate a stall*).
    ///
    /// Note: [`StallReason::AlreadyCommitted`] does not make `is_healthy`
    /// `false` — a committed height is a successful outcome.
    pub is_healthy: bool,
    /// Wall‑clock timestamp (ms since UNIX epoch).
    pub timestamp: u64,
    /// Elapsed time since entering the current step (ms).
    pub step_elapsed_ms: u64,
}

// -----------------------------------------------------------------------------
// Helper functions
// -----------------------------------------------------------------------------

/// Format a short public key (first N hex bytes).
fn short_pk(pk: &PublicKeyBytes) -> String {
    let len = HEX_SHORT_LEN.min(pk.0.len());
    if len == 0 {
        return "??".into();
    }
    hex::encode(&pk.0[..len])
}

/// Format a short string, char‑boundary safe.
///
/// Uses `chars()` so a non‑ASCII string (defensive — public keys are hex)
/// cannot trigger a byte‑slice panic.
fn short_pk_str(s: &str) -> String {
    let max = HEX_SHORT_LEN * 2;
    let mut out = String::with_capacity(max);
    for (i, c) in s.chars().enumerate() {
        if i >= max {
            break;
        }
        out.push(c);
    }
    out
}

/// Current wall‑clock time in milliseconds since the UNIX epoch.
#[inline]
fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// Generate a short summary string for a stall reason.
fn stall_reason_summary(reason: &StallReason) -> String {
    match reason {
        StallReason::WaitingForProposal { proposer, elapsed_ms, timeout_ms } => {
            format!("waiting_proposal(from={}, {}/{}ms)", proposer, elapsed_ms, timeout_ms)
        }
        StallReason::MissingBlock { block_id } => {
            format!("missing_block(id={})", block_id)
        }
        StallReason::InsufficientPrevotes { have, need, .. } => {
            format!("low_prevotes(have={} need={})", have, need)
        }
        StallReason::InsufficientPrecommits { have, need, .. } => {
            format!("low_precommits(have={} need={})", have, need)
        }
        StallReason::NoConnectedValidators { total_validators } => {
            format!("no_connected_validators(total={})", total_validators)
        }
        StallReason::InsufficientConnectedValidators { connected, total, needed } => {
            format!("low_connectivity(connected={}/{} need={})", connected, total, needed)
        }
        StallReason::AlreadyCommitted { height } => {
            format!("committed(height={})", height)
        }
        StallReason::RoundAdvancing { current_round, max_rounds } => {
            format!("round_advancing({}/{})", current_round, max_rounds)
        }
        StallReason::NoProposalInRound { round } => {
            format!("no_proposal(round={})", round)
        }
        StallReason::ProposerNotConnected { proposer } => {
            format!("proposer_not_connected({})", proposer)
        }
        StallReason::ProposerMismatch { expected, actual } => {
            format!("proposer_mismatch(expected={} actual={})", expected, actual)
        }
        StallReason::ProposalBlockHashMismatch { expected, actual } => {
            format!("block_hash_mismatch(expected={} actual={})", expected, actual)
        }
        StallReason::InvalidProposalSignature { proposer, reason } => {
            format!("invalid_proposal_sig({} reason={})", proposer, reason)
        }
        StallReason::QuorumNotReached { have, need } => {
            format!("quorum_not_reached(have={} need={})", have, need)
        }
        StallReason::NotProposer { proposer } => {
            format!("not_proposer({})", proposer)
        }
        StallReason::AlreadyVoted { vote_type } => {
            format!("already_voted({})", vote_type)
        }
        StallReason::TimedOut { step, elapsed_ms, timeout_ms } => {
            format!("timed_out(step={}, {}/{}ms)", step, elapsed_ms, timeout_ms)
        }
        StallReason::StaleMessage { reason } => {
            format!("stale_message({})", reason)
        }
        StallReason::DuplicateVote { validator, vote_type } => {
            format!("duplicate_vote({} for {})", validator, vote_type)
        }
    }
}

// -----------------------------------------------------------------------------
// Diagnostic Collector — Rate‑limited diagnostics
// -----------------------------------------------------------------------------

/// A collector that provides rate‑limited diagnostics and history.
///
/// # Cloning
///
/// Cloning shares the underlying state via `Arc<Mutex<...>>` — clones observe
/// each other's writes. This is intentional: a collector can be passed to a
/// background task while the main loop keeps its handle.
#[derive(Clone)]
pub struct DiagnosticCollector {
    config: DiagnosticConfig,
    stats: Arc<Mutex<DiagnosticStats>>,
    history: Arc<Mutex<VecDeque<ConsensusDiagnostic>>>,
    /// Bounded rate‑limiter map. `BTreeMap` gives O(log n) `pop_first` for
    /// oldest‑key eviction. Keys are `(height, round)`.
    last_diag_time: Arc<Mutex<BTreeMap<(u64, u32), Instant>>>,
}

impl DiagnosticCollector {
    /// Create a new diagnostic collector with the given configuration.
    ///
    /// Returns `Err(String)` if `config` is invalid — no panic.
    pub fn new(config: DiagnosticConfig) -> Result<Self, String> {
        config.validate()?;
        Ok(Self {
            config,
            stats: Arc::new(Mutex::new(DiagnosticStats::default())),
            history: Arc::new(Mutex::new(VecDeque::new())),
            last_diag_time: Arc::new(Mutex::new(BTreeMap::new())),
        })
    }

    /// Run a diagnostic, respecting the rate limit.
    ///
    /// Returns `Some(diagnostic)` if the rate limit allows, otherwise `None`.
    pub fn diagnose(
        &self,
        state: &ConsensusState,
        vset: &ValidatorSet,
        stake_ledger: &StakeLedger,
        connected_validators: &[PublicKeyBytes],
        step_elapsed_ms: u64,
        propose_timeout_ms: u64,
    ) -> Option<ConsensusDiagnostic> {
        let key = (state.height, state.round);
        let now = Instant::now();

        // ── Rate limit ────────────────────────────────────────────────────
        {
            let mut last_times = self.last_diag_time.lock();
            if let Some(last) = last_times.get(&key) {
                let interval = Duration::from_millis(self.config.min_diag_interval_ms);
                if now.duration_since(*last) < interval {
                    debug!(
                        height = state.height,
                        round = state.round,
                        "diagnostic rate-limited"
                    );
                    return None;
                }
            }
            last_times.insert(key, now);

            // Bound the map: evict oldest keys once we exceed the cap.
            while last_times.len() > MAX_RATE_LIMIT_ENTRIES {
                last_times.pop_first();
            }
        }

        let diag = diagnose_with_stake(
            state,
            vset,
            stake_ledger,
            connected_validators,
            step_elapsed_ms,
            propose_timeout_ms,
            &self.config,
        );

        // ── Statistics ────────────────────────────────────────────────────
        if self.config.enable_statistics {
            self.stats.lock().record(&diag);
        }

        // ── History ───────────────────────────────────────────────────────
        {
            let mut history = self.history.lock();
            while history.len() >= self.config.max_history {
                history.pop_front();
            }
            history.push_back(diag.clone());
        }

        Some(diag)
    }

    /// Get the current statistics.
    pub fn stats(&self) -> DiagnosticStats {
        self.stats.lock().clone()
    }

    /// Get the diagnostic history.
    pub fn history(&self) -> Vec<ConsensusDiagnostic> {
        self.history.lock().iter().cloned().collect()
    }

    /// Reset statistics.
    pub fn reset_stats(&self) {
        self.stats.lock().reset();
    }

    /// Clear history.
    pub fn clear_history(&self) {
        self.history.lock().clear();
    }

    /// Clear the rate‑limiter map. After this, the next `diagnose` for any
    /// `(height, round)` will succeed regardless of the interval.
    pub fn clear_rate_limits(&self) {
        self.last_diag_time.lock().clear();
    }

    /// Access the validated configuration.
    pub fn config(&self) -> &DiagnosticConfig {
        &self.config
    }
}

// -----------------------------------------------------------------------------
// Main diagnostic function with stake‑weighted quorum
// -----------------------------------------------------------------------------

/// Analyze the current consensus state and return diagnostics.
/// Uses `StakeLedger` for stake‑weighted quorum calculations.
///
/// This function is pure and allocation‑bounded: it allocates the returned
/// diagnostic (with `max_reasons` reasons), the quorum calculator, and a
/// `HashSet<&PublicKeyBytes>` for connectivity lookups.
#[must_use]
pub fn diagnose_with_stake(
    state: &ConsensusState,
    vset: &ValidatorSet,
    stake_ledger: &StakeLedger,
    connected_validators: &[PublicKeyBytes],
    step_elapsed_ms: u64,
    propose_timeout_ms: u64,
    config: &DiagnosticConfig,
) -> ConsensusDiagnostic {
    let timestamp = now_ms();
    let step_str = format!("{:?}", state.step);

    // ── Already committed ───────────────────────────────────────────────
    //
    // Not a stall — return early with `is_healthy = true`. The
    // `AlreadyCommitted` reason is carried for observability but does not
    // flip `is_healthy`, which drives the healthy/stalled classification
    // in `DiagnosticStats::record`.
    if state.decided.is_some() {
        return ConsensusDiagnostic {
            height: state.height,
            round: state.round,
            step: step_str,
            stall_reasons: vec![StallReason::AlreadyCommitted { height: state.height }],
            summary: format!("COMMITTED height={}", state.height),
            is_healthy: true,
            timestamp,
            step_elapsed_ms,
        };
    }

    let mut reasons: Vec<StallReason> = Vec::with_capacity(config.max_reasons);

    // ── Round advancement ───────────────────────────────────────────────
    if state.round >= config.max_rounds {
        reasons.push(StallReason::RoundAdvancing {
            current_round: state.round,
            max_rounds: config.max_rounds,
        });
    }

    // ── P2P connectivity ────────────────────────────────────────────────
    let quorum_calc = QuorumCalculator::new_with_stake(vset, stake_ledger);
    let connected_set: HashSet<&PublicKeyBytes> = connected_validators.iter().collect();
    let (connected_power, total_power) = quorum_calc.power_stats(&connected_set);

    if total_power == 0 {
        reasons.push(StallReason::NoConnectedValidators {
            total_validators: vset.vals.len(),
        });
    } else {
        let needed = quorum_calc.quorum_threshold_power();
        if connected_power < needed {
            reasons.push(StallReason::InsufficientConnectedValidators {
                connected: connected_validators.len(),
                total: vset.vals.len(),
                needed: needed as usize,
            });
        }
    }

    // ── Step‑specific checks ────────────────────────────────────────────
    match state.step {
        Step::Propose => {
            if state.proposal.is_none() {
                let proposer = vset.proposer_for(state.height, state.round);
                if !connected_set.contains(&proposer.pk) {
                    reasons.push(StallReason::ProposerNotConnected {
                        proposer: short_pk(&proposer.pk),
                    });
                }
                reasons.push(StallReason::WaitingForProposal {
                    proposer: short_pk(&proposer.pk),
                    elapsed_ms: step_elapsed_ms,
                    timeout_ms: propose_timeout_ms,
                });
            } else if state.proposal_block.is_none() {
                let block_id = state
                    .proposal
                    .as_ref()
                    .map(|p| hex::encode(&p.block_id.0[..HEX_SHORT_LEN]))
                    .unwrap_or_else(|| "??".into());
                reasons.push(StallReason::MissingBlock { block_id });
            }
        }
        Step::Prevote => {
            let voters: Vec<PublicKeyBytes> = state
                .votes
                .get(&state.round)
                .and_then(|rv| rv.get(&crate::consensus::messages::VoteType::Prevote))
                .map(|m| m.keys().cloned().collect())
                .unwrap_or_default();
            let diag = quorum_calc.check(&voters);
            if !diag.has_quorum {
                let (voted, missing) = if config.include_validator_details {
                    (
                        diag.voted.iter().map(|s| short_pk_str(s)).collect(),
                        diag.missing.iter().map(|s| short_pk_str(s)).collect(),
                    )
                } else {
                    (Vec::new(), Vec::new())
                };
                reasons.push(StallReason::InsufficientPrevotes {
                    have: diag.current_power,
                    need: diag.quorum_threshold,
                    voted,
                    missing,
                });
            }
        }
        Step::Precommit => {
            let voters: Vec<PublicKeyBytes> = state
                .votes
                .get(&state.round)
                .and_then(|rv| rv.get(&crate::consensus::messages::VoteType::Precommit))
                .map(|m| m.keys().cloned().collect())
                .unwrap_or_default();
            let diag = quorum_calc.check(&voters);
            if !diag.has_quorum {
                let (voted, missing) = if config.include_validator_details {
                    (
                        diag.voted.iter().map(|s| short_pk_str(s)).collect(),
                        diag.missing.iter().map(|s| short_pk_str(s)).collect(),
                    )
                } else {
                    (Vec::new(), Vec::new())
                };
                reasons.push(StallReason::InsufficientPrecommits {
                    have: diag.current_power,
                    need: diag.quorum_threshold,
                    voted,
                    missing,
                });
            }
        }
        Step::Commit => {
            // Not reached: `state.decided` short‑circuits above.
        }
    }

    // ── Truncate reasons ────────────────────────────────────────────────
    if reasons.len() > config.max_reasons {
        reasons.truncate(config.max_reasons);
    }

    // ── Build summary ───────────────────────────────────────────────────
    let is_healthy = reasons.is_empty();
    let summary = if is_healthy {
        format!("OK height={} round={} step={}", state.height, state.round, step_str)
    } else {
        let reason_strs: Vec<String> = reasons.iter().map(stall_reason_summary).collect();
        format!(
            "NO_COMMIT height={} round={} step={}: {}",
            state.height,
            state.round,
            step_str,
            reason_strs.join(", ")
        )
    };

    ConsensusDiagnostic {
        height: state.height,
        round: state.round,
        step: step_str,
        stall_reasons: reasons,
        summary,
        is_healthy,
        timestamp,
        step_elapsed_ms,
    }
}

// -----------------------------------------------------------------------------
// Legacy diagnose function (for backward compatibility)
// -----------------------------------------------------------------------------

/// Analyze the current consensus state and return diagnostics.
///
/// (Legacy; prefer [`diagnose_with_stake`] or [`DiagnosticCollector`].)
///
/// Uses a synthetic equal‑weight stake ledger derived from `vset.vals`.
/// If `stats` is provided, the diagnostic is recorded against it.
#[must_use]
pub fn diagnose(
    state: &ConsensusState,
    vset: &ValidatorSet,
    connected_validators: &[PublicKeyBytes],
    step_elapsed_ms: u64,
    propose_timeout_ms: u64,
    config: &DiagnosticConfig,
    stats: Option<&mut DiagnosticStats>,
) -> ConsensusDiagnostic {
    let mut ledger = StakeLedger::default();
    for v in &vset.vals {
        ledger.set_power(&v.pk, 1);
    }
    let diag = diagnose_with_stake(
        state,
        vset,
        &ledger,
        connected_validators,
        step_elapsed_ms,
        propose_timeout_ms,
        config,
    );
    if let Some(s) = stats {
        s.record(&diag);
    }
    diag
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::consensus::validator_set::{Validator, ValidatorSet};
    use crate::crypto::ed25519::Ed25519Keypair;
    use crate::crypto::Signer;
    use std::thread;

    const TEST_PROPOSE_TIMEOUT_MS: u64 = 300;

    fn make_vset_and_pks(n: usize) -> (ValidatorSet, Vec<PublicKeyBytes>) {
        let mut vals = Vec::with_capacity(n);
        let mut pks = Vec::with_capacity(n);
        for i in 0..n {
            let mut seed = [0u8; 32];
            seed[0] = (i + 1) as u8;
            let kp = Ed25519Keypair::from_seed(seed);
            let pk = kp.public_key();
            vals.push(Validator { pk: pk.clone(), power: 1 });
            pks.push(pk);
        }
        (ValidatorSet { vals }, pks)
    }

    fn default_config() -> DiagnosticConfig {
        DiagnosticConfig::default()
    }

    fn make_stake_ledger(vset: &ValidatorSet) -> StakeLedger {
        let mut ledger = StakeLedger::default();
        for v in &vset.vals {
            ledger.set_power(&v.pk, 1);
        }
        ledger
    }

    fn make_prevote_state(pks: &[PublicKeyBytes]) -> ConsensusState {
        let mut state = ConsensusState::new(1);
        state.step = Step::Prevote;
        let mut votes = HashMap::new();
        for pk in pks {
            votes.insert(
                pk.clone(),
                crate::consensus::messages::Vote {
                    validator: pk.clone(),
                    height: 1,
                    round: 0,
                    vote_type: crate::consensus::messages::VoteType::Prevote,
                    block_hash: Some(crate::types::Hash32::zero()),
                    signature: crate::crypto::SignatureBytes(vec![]),
                },
            );
        }
        let mut round_map = HashMap::new();
        round_map.insert(crate::consensus::messages::VoteType::Prevote, votes);
        state.votes.insert(0, round_map);
        state
    }

    // ── Basic scenario tests ────────────────────────────────────────────

    #[test]
    fn test_diagnose_committed() {
        let (vset, pks) = make_vset_and_pks(3);
        let ledger = make_stake_ledger(&vset);
        let mut state = ConsensusState::new(1);
        state.decided = Some(crate::consensus::engine::CommitCertificate {
            height: 1,
            block_id: crate::types::Hash32::zero(),
            precommits: vec![],
        });

        let diag = diagnose_with_stake(
            &state, &vset, &ledger, &pks, 0, TEST_PROPOSE_TIMEOUT_MS, &default_config(),
        );
        assert!(diag.is_healthy);
        assert!(diag.summary.contains("COMMITTED"));
        assert_eq!(diag.stall_reasons.len(), 1);
        assert!(matches!(
            diag.stall_reasons[0],
            StallReason::AlreadyCommitted { height: 1 }
        ));
    }

    #[test]
    fn test_diagnose_waiting_proposal() {
        let (vset, pks) = make_vset_and_pks(3);
        let ledger = make_stake_ledger(&vset);
        let state = ConsensusState::new(1);

        let diag = diagnose_with_stake(
            &state, &vset, &ledger, &pks, 100, TEST_PROPOSE_TIMEOUT_MS, &default_config(),
        );
        assert!(!diag.is_healthy);
        assert!(diag.summary.contains("waiting_proposal"));
    }

    #[test]
    fn test_diagnose_no_connected_validators() {
        let (vset, _pks) = make_vset_and_pks(3);
        let ledger = make_stake_ledger(&vset);
        let state = ConsensusState::new(1);

        let diag = diagnose_with_stake(
            &state, &vset, &ledger, &[], 100, TEST_PROPOSE_TIMEOUT_MS, &default_config(),
        );
        assert!(!diag.is_healthy);
        assert!(
            diag.summary.contains("no_connected_validators")
                || diag.summary.contains("low_connectivity")
        );
    }

    #[test]
    fn test_diagnose_insufficient_connectivity() {
        let (vset, pks) = make_vset_and_pks(4);
        let ledger = make_stake_ledger(&vset);
        let state = ConsensusState::new(1);

        let diag = diagnose_with_stake(
            &state, &vset, &ledger, &pks[..1], 100, TEST_PROPOSE_TIMEOUT_MS, &default_config(),
        );
        assert!(!diag.is_healthy);
        assert!(diag.summary.contains("low_connectivity"));
    }

    #[test]
    fn test_diagnose_healthy_when_quorum_met() {
        let (vset, pks) = make_vset_and_pks(3);
        let ledger = make_stake_ledger(&vset);
        let state = make_prevote_state(&pks);

        let diag = diagnose_with_stake(
            &state, &vset, &ledger, &pks, 0, TEST_PROPOSE_TIMEOUT_MS, &default_config(),
        );
        assert!(diag.is_healthy);
        assert!(diag.summary.contains("OK"));
    }

    // ── Configuration tests ─────────────────────────────────────────────

    #[test]
    fn test_config_validation() {
        assert!(DiagnosticConfig::default().validate().is_ok());
        assert!(DiagnosticConfig { max_reasons: 0, ..Default::default() }.validate().is_err());
        assert!(DiagnosticConfig { max_rounds: 0, ..Default::default() }.validate().is_err());
        assert!(DiagnosticConfig { min_diag_interval_ms: 0, ..Default::default() }.validate().is_err());
        assert!(DiagnosticConfig { max_history: 0, ..Default::default() }.validate().is_err());
        assert!(DiagnosticConfig {
            max_reasons: MAX_ALLOWED_REASONS + 1,
            ..Default::default()
        }.validate().is_err());
        assert!(DiagnosticConfig {
            max_history: MAX_ALLOWED_HISTORY + 1,
            ..Default::default()
        }.validate().is_err());
    }

    #[test]
    fn test_collector_new_rejects_invalid_config() {
        let cfg = DiagnosticConfig { max_reasons: 0, ..Default::default() };
        assert!(DiagnosticCollector::new(cfg).is_err());
    }

    // ── Statistics tests ────────────────────────────────────────────────

    #[test]
    fn test_statistics_tracking() {
        let (vset, pks) = make_vset_and_pks(3);
        let ledger = make_stake_ledger(&vset);
        let mut stats = DiagnosticStats::default();

        // Healthy
        let healthy_state = make_prevote_state(&pks);
        let diag = diagnose_with_stake(
            &healthy_state, &vset, &ledger, &pks, 0, TEST_PROPOSE_TIMEOUT_MS, &default_config(),
        );
        stats.record(&diag);
        assert_eq!(stats.total_diagnostics, 1);
        assert_eq!(stats.healthy_count, 1);
        assert_eq!(stats.stalled_count, 0);

        // Stalled
        let state = ConsensusState::new(1);
        let diag = diagnose_with_stake(
            &state, &vset, &ledger, &[], 100, TEST_PROPOSE_TIMEOUT_MS, &default_config(),
        );
        stats.record(&diag);
        assert_eq!(stats.total_diagnostics, 2);
        assert_eq!(stats.healthy_count, 1);
        assert_eq!(stats.stalled_count, 1);
        assert!(stats.reason_counts.values().sum::<u64>() > 0);
    }

    #[test]
    fn test_statistics_already_committed_not_counted_as_stall() {
        // Regression: previously `record` classified by `reasons.is_empty()`,
        // so a committed height (with one AlreadyCommitted reason) was
        // wrongly counted as stalled.
        let (vset, pks) = make_vset_and_pks(3);
        let ledger = make_stake_ledger(&vset);
        let mut state = ConsensusState::new(1);
        state.decided = Some(crate::consensus::engine::CommitCertificate {
            height: 1,
            block_id: crate::types::Hash32::zero(),
            precommits: vec![],
        });
        let diag = diagnose_with_stake(
            &state, &vset, &ledger, &pks, 0, TEST_PROPOSE_TIMEOUT_MS, &default_config(),
        );
        let mut stats = DiagnosticStats::default();
        stats.record(&diag);
        assert_eq!(stats.healthy_count, 1);
        assert_eq!(stats.stalled_count, 0);
    }

    // ── Round advancement ───────────────────────────────────────────────

    #[test]
    fn test_diagnose_round_advancing() {
        let (vset, pks) = make_vset_and_pks(3);
        let ledger = make_stake_ledger(&vset);
        let mut state = ConsensusState::new(1);
        state.round = 15;

        let diag = diagnose_with_stake(
            &state, &vset, &ledger, &pks, 0, TEST_PROPOSE_TIMEOUT_MS, &default_config(),
        );
        assert!(!diag.is_healthy);
        assert!(diag.summary.contains("round_advancing"));
    }

    #[test]
    fn test_max_reasons_truncation() {
        let (vset, _pks) = make_vset_and_pks(1);
        let ledger = make_stake_ledger(&vset);
        let mut state = ConsensusState::new(1);
        state.round = 20;
        let config = DiagnosticConfig { max_reasons: 1, ..Default::default() };

        let diag = diagnose_with_stake(
            &state, &vset, &ledger, &[], 100, TEST_PROPOSE_TIMEOUT_MS, &config,
        );
        assert_eq!(diag.stall_reasons.len(), 1);
    }

    // ── DiagnosticCollector tests ───────────────────────────────────────

    #[test]
    fn test_diagnostic_collector_rate_limit() {
        let (vset, pks) = make_vset_and_pks(3);
        let ledger = make_stake_ledger(&vset);
        let state = ConsensusState::new(1);
        let config = DiagnosticConfig {
            min_diag_interval_ms: 1000,
            ..Default::default()
        };
        let collector = DiagnosticCollector::new(config).unwrap();

        assert!(collector
            .diagnose(&state, &vset, &ledger, &pks, 0, TEST_PROPOSE_TIMEOUT_MS)
            .is_some());
        assert!(collector
            .diagnose(&state, &vset, &ledger, &pks, 0, TEST_PROPOSE_TIMEOUT_MS)
            .is_none());

        // Clearing rate limits allows the next call.
        collector.clear_rate_limits();
        assert!(collector
            .diagnose(&state, &vset, &ledger, &pks, 0, TEST_PROPOSE_TIMEOUT_MS)
            .is_some());
    }

    #[test]
    fn test_diagnostic_collector_history() {
        let (vset, pks) = make_vset_and_pks(3);
        let ledger = make_stake_ledger(&vset);
        let state = ConsensusState::new(1);
        let config = DiagnosticConfig {
            min_diag_interval_ms: 1,
            max_history: 3,
            ..Default::default()
        };
        let collector = DiagnosticCollector::new(config).unwrap();

        for h in 1..=5u64 {
            let mut s = state.clone();
            s.height = h;
            assert!(collector
                .diagnose(&s, &vset, &ledger, &pks, 0, TEST_PROPOSE_TIMEOUT_MS)
                .is_some());
            // 20ms is enough to clear the 1ms rate limit even on loaded CI.
            thread::sleep(Duration::from_millis(20));
        }

        let history = collector.history();
        assert_eq!(history.len(), 3);
        assert_eq!(history[0].height, 3);
        assert_eq!(history[2].height, 5);
    }

    #[test]
    fn test_diagnostic_collector_rate_limit_map_bounded() {
        // The rate limiter should not grow beyond MAX_RATE_LIMIT_ENTRIES.
        let (vset, pks) = make_vset_and_pks(1);
        let ledger = make_stake_ledger(&vset);
        let config = DiagnosticConfig {
            min_diag_interval_ms: 1,
            ..Default::default()
        };
        let collector = DiagnosticCollector::new(config).unwrap();

        for h in 0..(MAX_RATE_LIMIT_ENTRIES as u64 + 100) {
            let mut s = ConsensusState::new(h);
            s.height = h;
            let _ = collector.diagnose(&s, &vset, &ledger, &pks, 0, TEST_PROPOSE_TIMEOUT_MS);
        }
        let map_len = collector.last_diag_time.lock().len();
        assert!(map_len <= MAX_RATE_LIMIT_ENTRIES);
    }

    // ── Serialization ───────────────────────────────────────────────────

    #[test]
    fn test_diagnostic_serialization() {
        let (vset, pks) = make_vset_and_pks(3);
        let ledger = make_stake_ledger(&vset);
        let state = ConsensusState::new(1);
        let diag = diagnose_with_stake(
            &state, &vset, &ledger, &pks, 100, TEST_PROPOSE_TIMEOUT_MS, &default_config(),
        );

        let json = serde_json::to_string(&diag).unwrap();
        assert!(json.contains("height"));
        assert!(json.contains("round"));
        assert!(json.contains("summary"));

        let deserialized: ConsensusDiagnostic = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.height, diag.height);
        assert_eq!(deserialized.is_healthy, diag.is_healthy);
    }

    #[test]
    fn test_stall_reason_summaries() {
        let reason = StallReason::WaitingForProposal {
            proposer: "val1".into(),
            elapsed_ms: 150,
            timeout_ms: 300,
        };
        let summary = stall_reason_summary(&reason);
        assert!(summary.contains("150/300ms"));

        let reason = StallReason::InsufficientConnectedValidators {
            connected: 2,
            total: 4,
            needed: 3,
        };
        let summary = stall_reason_summary(&reason);
        assert!(summary.contains("2/4"));
        assert!(summary.contains("need=3"));
    }

    #[test]
    fn test_short_pk() {
        let pk = PublicKeyBytes([0xAA; 32]);
        let short = short_pk(&pk);
        assert_eq!(short.len(), 16);
        assert_eq!(short, "aaaaaaaaaaaaaaaa");
    }

    #[test]
    fn test_short_pk_str_handles_non_ascii() {
        // Regression: previously used `&s[..16]` which panics on a
        // non‑UTF‑8 boundary.
        let s = "éééééééééééééééééééé";
        let out = short_pk_str(s);
        // Should not panic, should not split a char.
        assert!(out.chars().count() <= HEX_SHORT_LEN * 2);
    }
}
