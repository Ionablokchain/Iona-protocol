//! Consensus diagnostic module for IONA v28 — Production‑Grade.
//!
//! When consensus stalls, this module provides a clear, single‑line answer
//! to "why no commit?" instead of requiring you to read multiple logs.
//!
//! # Features
//! - Multi‑reason stall detection (proposal, votes, connectivity, rounds).
//! - Quorum‑aware diagnostics using `QuorumCalculator` with stake‑weighted power.
//! - Human‑readable summaries for logging and monitoring.
//! - Configurable diagnostic parameters.
//! - Statistics tracking for operational insights.
//! - Rate‑limited diagnostics to avoid log spam.
//! - Optional Prometheus metrics integration.
//!
//! # Example output
//! ```text
//! NO_COMMIT height=42 round=0: waiting_proposal(from=val1, 150/300ms),
//!   low_connectivity(connected=2/4 need=3)
//! ```

use crate::consensus::engine::{ConsensusState, Step};
use crate::consensus::quorum_diag::{QuorumCalculator, QuorumDiagnostic};
use crate::consensus::validator_set::ValidatorSet;
use crate::crypto::PublicKeyBytes;
use crate::slashing::StakeLedger;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tracing::{debug, info, warn};

// -----------------------------------------------------------------------------
// Constants
// -----------------------------------------------------------------------------

/// Prefix length for hex‑shortened public keys in logs.
const HEX_SHORT_LEN: usize = 8;

/// Default maximum number of stall reasons to include.
const DEFAULT_MAX_REASONS: usize = 5;

/// Default maximum rounds before flagging round advancement.
const DEFAULT_MAX_ROUNDS: u32 = 10;

/// Default minimum interval between diagnostics for the same height/round (milliseconds).
const DEFAULT_MIN_DIAG_INTERVAL_MS: u64 = 5000;

/// Default maximum number of historical diagnostics to keep.
const DEFAULT_MAX_HISTORY: usize = 100;

// -----------------------------------------------------------------------------
// Configuration
// -----------------------------------------------------------------------------

/// Configuration for the diagnostic module.
#[derive(Debug, Clone, Serialize, Deserialize)]
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
    /// Whether to emit Prometheus metrics (if feature enabled).
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
    pub fn validate(&self) -> Result<(), String> {
        if self.max_reasons == 0 {
            return Err("max_reasons must be > 0".into());
        }
        if self.max_rounds == 0 {
            return Err("max_rounds must be > 0".into());
        }
        if self.min_diag_interval_ms == 0 {
            return Err("min_diag_interval_ms must be > 0".into());
        }
        Ok(())
    }
}

// -----------------------------------------------------------------------------
// Statistics
// -----------------------------------------------------------------------------

/// Statistics collected during diagnostic operations.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
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
    pub fn record(&mut self, reasons: &[StallReason]) {
        self.total_diagnostics += 1;
        if reasons.is_empty() {
            self.healthy_count += 1;
        } else {
            self.stalled_count += 1;
            let n = self.stalled_count as f64;
            self.avg_reasons_per_stall = (self.avg_reasons_per_stall * (n - 1.0)
                + reasons.len() as f64)
                / n;
            for reason in reasons {
                let key = reason_type_name(reason);
                *self.reason_counts.entry(key).or_insert(0) += 1;
            }
        }
    }

    /// Reset all statistics.
    pub fn reset(&mut self) {
        *self = Self::default();
    }
}

/// Return a stable string name for a stall reason variant.
fn reason_type_name(reason: &StallReason) -> String {
    match reason {
        StallReason::WaitingForProposal { .. } => "waiting_for_proposal".into(),
        StallReason::MissingBlock { .. } => "missing_block".into(),
        StallReason::InsufficientPrevotes { .. } => "insufficient_prevotes".into(),
        StallReason::InsufficientPrecommits { .. } => "insufficient_precommits".into(),
        StallReason::NoConnectedValidators { .. } => "no_connected_validators".into(),
        StallReason::InsufficientConnectedValidators { .. } => {
            "insufficient_connected_validators".into()
        }
        StallReason::AlreadyCommitted { .. } => "already_committed".into(),
        StallReason::RoundAdvancing { .. } => "round_advancing".into(),
        StallReason::NoProposalInRound { .. } => "no_proposal_in_round".into(),
        StallReason::ProposerNotConnected { .. } => "proposer_not_connected".into(),
        StallReason::ProposerMismatch { .. } => "proposer_mismatch".into(),
        StallReason::ProposalBlockHashMismatch { .. } => "proposal_block_hash_mismatch".into(),
        StallReason::InvalidProposalSignature { .. } => "invalid_proposal_signature".into(),
        StallReason::QuorumNotReached { .. } => "quorum_not_reached".into(),
        StallReason::NotProposer { .. } => "not_proposer".into(),
        StallReason::AlreadyVoted { .. } => "already_voted".into(),
        StallReason::TimedOut { .. } => "timed_out".into(),
        StallReason::StaleMessage { .. } => "stale_message".into(),
        StallReason::DuplicateVote { .. } => "duplicate_vote".into(),
    }
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
    MissingBlock {
        block_id: String,
    },
    /// Not enough prevotes to proceed.
    InsufficientPrevotes {
        have: u64,
        need: u64,
        #[serde(skip_serializing_if = "Vec::is_empty")]
        voted: Vec<String>,
        #[serde(skip_serializing_if = "Vec::is_empty")]
        missing: Vec<String>,
    },
    /// Not enough precommits to commit.
    InsufficientPrecommits {
        have: u64,
        need: u64,
        #[serde(skip_serializing_if = "Vec::is_empty")]
        voted: Vec<String>,
        #[serde(skip_serializing_if = "Vec::is_empty")]
        missing: Vec<String>,
    },
    /// No connected validators (P2P issue).
    NoConnectedValidators {
        total_validators: usize,
    },
    /// Too few connected validators for quorum.
    InsufficientConnectedValidators {
        connected: usize,
        total: usize,
        needed: usize,
    },
    /// Already committed at this height.
    AlreadyCommitted {
        height: u64,
    },
    /// Round is advancing (timeout‑driven).
    RoundAdvancing {
        current_round: u32,
        max_rounds: u32,
    },
    /// No proposal for this round (missing block or message).
    NoProposalInRound {
        round: u32,
    },
    /// Designated proposer is not connected.
    ProposerNotConnected {
        proposer: String,
    },
    /// The received proposal has a different proposer than expected.
    ProposerMismatch {
        expected: String,
        actual: String,
    },
    /// The block hash in the proposal does not match the block.
    ProposalBlockHashMismatch {
        expected: String,
        actual: String,
    },
    /// Invalid signature on the proposal.
    InvalidProposalSignature {
        proposer: String,
        reason: String,
    },
    /// General quorum not reached (aggregate power).
    QuorumNotReached {
        have: u64,
        need: u64,
    },
    /// This node is not the proposer for the round.
    NotProposer {
        proposer: String,
    },
    /// Already voted in this round (duplicate attempt).
    AlreadyVoted {
        vote_type: String,
    },
    /// Step timeout reached.
    TimedOut {
        step: String,
        elapsed_ms: u64,
        timeout_ms: u64,
    },
    /// Stale message (height/round mismatch).
    StaleMessage {
        reason: String,
    },
    /// Duplicate vote from the same validator.
    DuplicateVote {
        validator: String,
        vote_type: String,
    },
}

// -----------------------------------------------------------------------------
// Diagnostic snapshot
// -----------------------------------------------------------------------------

/// Full diagnostic snapshot.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConsensusDiagnostic {
    pub height: u64,
    pub round: u32,
    pub step: String,
    pub stall_reasons: Vec<StallReason>,
    /// One‑line summary for quick logging.
    pub summary: String,
    /// Whether consensus is healthy (no stall reasons).
    pub is_healthy: bool,
    /// Timestamp of the diagnostic.
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

/// Generate a short summary string for a stall reason.
fn stall_reason_summary(reason: &StallReason) -> String {
    match reason {
        StallReason::WaitingForProposal {
            proposer,
            elapsed_ms,
            timeout_ms,
        } => {
            format!(
                "waiting_proposal(from={}, {}/{}ms)",
                proposer, elapsed_ms, timeout_ms
            )
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
        StallReason::InsufficientConnectedValidators {
            connected,
            total,
            needed,
        } => {
            format!(
                "low_connectivity(connected={}/{} need={})",
                connected, total, needed
            )
        }
        StallReason::AlreadyCommitted { height } => {
            format!("committed(height={})", height)
        }
        StallReason::RoundAdvancing {
            current_round,
            max_rounds,
        } => {
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
#[derive(Clone)]
pub struct DiagnosticCollector {
    config: DiagnosticConfig,
    stats: Arc<std::sync::Mutex<DiagnosticStats>>,
    history: Arc<std::sync::Mutex<VecDeque<ConsensusDiagnostic>>>,
    last_diag_time: Arc<std::sync::Mutex<HashMap<(u64, u32), Instant>>>,
}

impl DiagnosticCollector {
    /// Create a new diagnostic collector with the given configuration.
    pub fn new(config: DiagnosticConfig) -> Self {
        config.validate().expect("invalid diagnostic config");
        Self {
            config,
            stats: Arc::new(std::sync::Mutex::new(DiagnosticStats::default())),
            history: Arc::new(std::sync::Mutex::new(VecDeque::new())),
            last_diag_time: Arc::new(std::sync::Mutex::new(HashMap::new())),
        }
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

        // Check rate limit
        {
            let mut last_times = self.last_diag_time.lock().unwrap();
            if let Some(last) = last_times.get(&key) {
                let interval = Duration::from_millis(self.config.min_diag_interval_ms);
                if now.duration_since(*last) < interval {
                    return None;
                }
            }
            last_times.insert(key, now);
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

        // Update statistics
        if self.config.enable_statistics {
            if let Ok(mut stats) = self.stats.lock() {
                stats.record(&diag.stall_reasons);
            }
        }

        // Update history
        if let Ok(mut history) = self.history.lock() {
            if history.len() >= self.config.max_history {
                history.pop_front();
            }
            history.push_back(diag.clone());
        }

        Some(diag)
    }

    /// Get the current statistics.
    pub fn stats(&self) -> DiagnosticStats {
        self.stats.lock().unwrap().clone()
    }

    /// Get the diagnostic history.
    pub fn history(&self) -> Vec<ConsensusDiagnostic> {
        self.history.lock().unwrap().iter().cloned().collect()
    }

    /// Reset statistics.
    pub fn reset_stats(&self) {
        self.stats.lock().unwrap().reset();
    }

    /// Clear history.
    pub fn clear_history(&self) {
        self.history.lock().unwrap().clear();
    }
}

// -----------------------------------------------------------------------------
// Main diagnostic function with stake‑weighted quorum
// -----------------------------------------------------------------------------

/// Analyze the current consensus state and return diagnostics.
/// Uses `StakeLedger` for stake‑weighted quorum calculations.
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
    let mut reasons = Vec::new();
    let quorum_calc = QuorumCalculator::new_with_stake(vset, stake_ledger);

    // ── Check if already committed ──────────────────────────────────────
    if state.decided.is_some() {
        let diag = ConsensusDiagnostic {
            height: state.height,
            round: state.round,
            step: format!("{:?}", state.step),
            stall_reasons: vec![StallReason::AlreadyCommitted {
                height: state.height,
            }],
            summary: format!("COMMITTED height={}", state.height),
            is_healthy: true,
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_millis() as u64,
            step_elapsed_ms,
        };
        return diag;
    }

    // ── Check round advancement ─────────────────────────────────────────
    if state.round >= config.max_rounds {
        reasons.push(StallReason::RoundAdvancing {
            current_round: state.round,
            max_rounds: config.max_rounds,
        });
    }

    // ── Check P2P connectivity to validators ────────────────────────────
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
                // Check if proposer is connected
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
            // If proposal exists but block is available, no stall reason here.
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
                let voted = if config.include_validator_details {
                    diag.voted.iter().map(|s| short_pk_str(s)).collect()
                } else {
                    vec![]
                };
                let missing = if config.include_validator_details {
                    diag.missing.iter().map(|s| short_pk_str(s)).collect()
                } else {
                    vec![]
                };
                reasons.push(StallReason::InsufficientPrevotes {
                    have: diag.current_power,
                    need: diag.quorum_threshold,
                    voted,
                    missing,
                });
            }
            // Also check if we already voted
            // This would need access to local voting status; for now skip.
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
                let voted = if config.include_validator_details {
                    diag.voted.iter().map(|s| short_pk_str(s)).collect()
                } else {
                    vec![]
                };
                let missing = if config.include_validator_details {
                    diag.missing.iter().map(|s| short_pk_str(s)).collect()
                } else {
                    vec![]
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
            // Already handled by decided check above.
        }
    }

    // ── Truncate reasons if too many ────────────────────────────────────
    if reasons.len() > config.max_reasons {
        reasons.truncate(config.max_reasons);
    }

    // ── Build summary ───────────────────────────────────────────────────
    let is_healthy = reasons.is_empty();
    let summary = if is_healthy {
        format!(
            "OK height={} round={} step={:?}",
            state.height, state.round, state.step
        )
    } else {
        let reason_strs: Vec<String> = reasons.iter().map(stall_reason_summary).collect();
        format!(
            "NO_COMMIT height={} round={} step={:?}: {}",
            state.height,
            state.round,
            state.step,
            reason_strs.join(", ")
        )
    };

    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64;

    ConsensusDiagnostic {
        height: state.height,
        round: state.round,
        step: format!("{:?}", state.step),
        stall_reasons: reasons,
        summary,
        is_healthy,
        timestamp,
        step_elapsed_ms,
    }
}

/// Shorter version of `short_pk` that returns a String directly.
fn short_pk_str(pk: &str) -> String {
    if pk.len() <= HEX_SHORT_LEN * 2 {
        pk.to_string()
    } else {
        pk[..HEX_SHORT_LEN * 2].to_string()
    }
}

// -----------------------------------------------------------------------------
// Legacy diagnose function (for backward compatibility)
// -----------------------------------------------------------------------------

/// Analyze the current consensus state and return diagnostics.
/// (Legacy version; prefer `diagnose_with_stake` or `DiagnosticCollector`.)
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
    // Use a dummy stake ledger where all validators have equal power.
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
        s.record(&diag.stall_reasons);
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

    const TEST_PROPOSE_TIMEOUT_MS: u64 = 300;

    fn make_vset_and_pks(n: usize) -> (ValidatorSet, Vec<PublicKeyBytes>) {
        let mut vals = Vec::new();
        let mut pks = Vec::new();
        for i in 0..n {
            let mut seed = [0u8; 32];
            seed[0] = (i + 1) as u8;
            let kp = Ed25519Keypair::from_seed(seed);
            let pk = kp.public_key();
            vals.push(Validator {
                pk: pk.clone(),
                power: 1,
            });
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

        let diag = diagnose_with_stake(&state, &vset, &ledger, &pks, 0, TEST_PROPOSE_TIMEOUT_MS, &default_config());
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

        let diag = diagnose_with_stake(&state, &vset, &ledger, &pks, 100, TEST_PROPOSE_TIMEOUT_MS, &default_config());
        assert!(!diag.is_healthy);
        assert!(diag.summary.contains("waiting_proposal"));
    }

    #[test]
    fn test_diagnose_no_connected_validators() {
        let (vset, _pks) = make_vset_and_pks(3);
        let ledger = make_stake_ledger(&vset);
        let state = ConsensusState::new(1);

        let diag = diagnose_with_stake(&state, &vset, &ledger, &[], 100, TEST_PROPOSE_TIMEOUT_MS, &default_config());
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

        // Only 1 of 4 connected — not enough for quorum of 3.
        let diag = diagnose_with_stake(&state, &vset, &ledger, &pks[..1], 100, TEST_PROPOSE_TIMEOUT_MS, &default_config());
        assert!(!diag.is_healthy);
        assert!(diag.summary.contains("low_connectivity"));
    }

    #[test]
    fn test_diagnose_ok_when_all_connected() {
        let (vset, pks) = make_vset_and_pks(3);
        let ledger = make_stake_ledger(&vset);
        let state = ConsensusState::new(1);

        let diag = diagnose_with_stake(&state, &vset, &ledger, &pks, 0, TEST_PROPOSE_TIMEOUT_MS, &default_config());
        // All connected, but no proposal yet → waiting_proposal (not "OK").
        assert!(!diag.is_healthy);
        assert!(diag.summary.contains("waiting_proposal"));
    }

    #[test]
    fn test_diagnose_healthy_when_quorum_met() {
        let (vset, pks) = make_vset_and_pks(3);
        let ledger = make_stake_ledger(&vset);
        let mut state = ConsensusState::new(1);
        state.step = Step::Prevote;
        // Simulate all 3 validators having prevoted
        let mut votes = std::collections::HashMap::new();
        for pk in &pks {
            votes.insert(pk.clone(), crate::consensus::messages::Vote {
                validator: pk.clone(),
                height: 1,
                round: 0,
                vote_type: crate::consensus::messages::VoteType::Prevote,
                block_hash: Some(crate::types::Hash32::zero()),
                signature: crate::crypto::SignatureBytes(vec![]),
            });
        }
        let mut round_map = std::collections::HashMap::new();
        round_map.insert(crate::consensus::messages::VoteType::Prevote, votes);
        state.votes.insert(0, round_map);

        let diag = diagnose_with_stake(&state, &vset, &ledger, &pks, 0, TEST_PROPOSE_TIMEOUT_MS, &default_config());
        assert!(diag.is_healthy);
        assert!(diag.summary.contains("OK"));
    }

    // ── Configuration tests ─────────────────────────────────────────────
    #[test]
    fn test_config_validation() {
        assert!(DiagnosticConfig::default().validate().is_ok());
        assert!(DiagnosticConfig {
            max_reasons: 0,
            ..Default::default()
        }
        .validate()
        .is_err());
        assert!(DiagnosticConfig {
            max_rounds: 0,
            ..Default::default()
        }
        .validate()
        .is_err());
        assert!(DiagnosticConfig {
            min_diag_interval_ms: 0,
            ..Default::default()
        }
        .validate()
        .is_err());
    }

    // ── Statistics tests ────────────────────────────────────────────────
    #[test]
    fn test_statistics_tracking() {
        let (vset, pks) = make_vset_and_pks(3);
        let ledger = make_stake_ledger(&vset);
        let state = ConsensusState::new(1);
        let mut stats = DiagnosticStats::default();

        // Run healthy diagnostic
        let mut healthy_state = state.clone();
        healthy_state.step = Step::Prevote;
        let mut votes = std::collections::HashMap::new();
        for pk in &pks {
            votes.insert(pk.clone(), crate::consensus::messages::Vote {
                validator: pk.clone(),
                height: 1,
                round: 0,
                vote_type: crate::consensus::messages::VoteType::Prevote,
                block_hash: Some(crate::types::Hash32::zero()),
                signature: crate::crypto::SignatureBytes(vec![]),
            });
        }
        let mut round_map = std::collections::HashMap::new();
        round_map.insert(crate::consensus::messages::VoteType::Prevote, votes);
        healthy_state.votes.insert(0, round_map);

        let diag = diagnose_with_stake(&healthy_state, &vset, &ledger, &pks, 0, TEST_PROPOSE_TIMEOUT_MS, &default_config());
        stats.record(&diag.stall_reasons);
        assert_eq!(stats.total_diagnostics, 1);
        assert_eq!(stats.healthy_count, 1);
        assert_eq!(stats.stalled_count, 0);

        // Run stalled diagnostic
        let diag = diagnose_with_stake(&state, &vset, &ledger, &[], 100, TEST_PROPOSE_TIMEOUT_MS, &default_config());
        stats.record(&diag.stall_reasons);
        assert_eq!(stats.total_diagnostics, 2);
        assert_eq!(stats.healthy_count, 1);
        assert_eq!(stats.stalled_count, 1);
        assert!(stats.reason_counts.values().sum::<u64>() > 0);
    }

    // ── Round advancement test ──────────────────────────────────────────
    #[test]
    fn test_diagnose_round_advancing() {
        let (vset, pks) = make_vset_and_pks(3);
        let ledger = make_stake_ledger(&vset);
        let mut state = ConsensusState::new(1);
        state.round = 15; // exceeds default max_rounds of 10

        let diag = diagnose_with_stake(&state, &vset, &ledger, &pks, 0, TEST_PROPOSE_TIMEOUT_MS, &default_config());
        assert!(!diag.is_healthy);
        assert!(diag.summary.contains("round_advancing"));
    }

    // ── Reason truncation test ──────────────────────────────────────────
    #[test]
    fn test_max_reasons_truncation() {
        let (vset, _pks) = make_vset_and_pks(1);
        let ledger = make_stake_ledger(&vset);
        let mut state = ConsensusState::new(1);
        state.round = 20; // triggers round_advancing
        // No connected validators → triggers connectivity issues
        let config = DiagnosticConfig {
            max_reasons: 1,
            ..Default::default()
        };

        let diag = diagnose_with_stake(&state, &vset, &ledger, &[], 100, TEST_PROPOSE_TIMEOUT_MS, &config);
        assert_eq!(diag.stall_reasons.len(), 1);
    }

    // ── DiagnosticCollector tests ────────────────────────────────────────
    #[test]
    fn test_diagnostic_collector_rate_limit() {
        let (vset, pks) = make_vset_and_pks(3);
        let ledger = make_stake_ledger(&vset);
        let state = ConsensusState::new(1);
        let config = DiagnosticConfig {
            min_diag_interval_ms: 1000,
            ..Default::default()
        };
        let collector = DiagnosticCollector::new(config);

        // First call should return Some
        let diag = collector.diagnose(&state, &vset, &ledger, &pks, 0, TEST_PROPOSE_TIMEOUT_MS);
        assert!(diag.is_some());

        // Second call immediately should return None (rate limited)
        let diag2 = collector.diagnose(&state, &vset, &ledger, &pks, 0, TEST_PROPOSE_TIMEOUT_MS);
        assert!(diag2.is_none());
    }

    #[test]
    fn test_diagnostic_collector_history() {
        let (vset, pks) = make_vset_and_pks(3);
        let ledger = make_stake_ledger(&vset);
        let state = ConsensusState::new(1);
        let config = DiagnosticConfig {
            min_diag_interval_ms: 1, // Allow quick calls
            max_history: 3,
            ..Default::default()
        };
        let collector = DiagnosticCollector::new(config);

        // Run multiple diagnostics with different heights
        for h in 1..=5 {
            let mut s = state.clone();
            s.height = h;
            let diag = collector.diagnose(&s, &vset, &ledger, &pks, 0, TEST_PROPOSE_TIMEOUT_MS);
            assert!(diag.is_some());
            std::thread::sleep(std::time::Duration::from_millis(5));
        }

        let history = collector.history();
        assert_eq!(history.len(), 3); // max_history = 3
        assert_eq!(history[0].height, 3);
        assert_eq!(history[2].height, 5);
    }

    // ── Serialization test ──────────────────────────────────────────────
    #[test]
    fn test_diagnostic_serialization() {
        let (vset, pks) = make_vset_and_pks(3);
        let ledger = make_stake_ledger(&vset);
        let state = ConsensusState::new(1);
        let diag = diagnose_with_stake(&state, &vset, &ledger, &pks, 100, TEST_PROPOSE_TIMEOUT_MS, &default_config());

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
        assert_eq!(short.len(), 16); // 8 bytes * 2 hex chars
        assert_eq!(short, "aaaaaaaaaaaaaaaa");
    }
}
