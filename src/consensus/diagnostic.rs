//! Consensus diagnostic module for IONA v28 — Production‑Grade.
//!
//! When consensus stalls, this module provides a clear, single‑line answer
//! to "why no commit?" instead of requiring you to read multiple logs.
//!
//! # Features
//! - Multi‑reason stall detection (proposal, votes, connectivity, rounds).
//! - Quorum‑aware diagnostics using `QuorumCalculator`.
//! - Human‑readable summaries for logging and monitoring.
//! - Configurable diagnostic parameters.
//! - Statistics tracking for operational insights.
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
use serde::{Deserialize, Serialize};
use std::collections::HashSet;

// -----------------------------------------------------------------------------
// Constants
// -----------------------------------------------------------------------------

/// Prefix length for hex‑shortened public keys in logs.
const HEX_SHORT_LEN: usize = 8;

/// Default maximum number of stall reasons to include.
const DEFAULT_MAX_REASONS: usize = 5;

/// Default maximum rounds before flagging round advancement.
const DEFAULT_MAX_ROUNDS: u32 = 10;

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
}

impl Default for DiagnosticConfig {
    fn default() -> Self {
        Self {
            max_reasons: DEFAULT_MAX_REASONS,
            max_rounds: DEFAULT_MAX_ROUNDS,
            include_validator_details: true,
            enable_statistics: true,
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
    pub reason_counts: std::collections::HashMap<String, u64>,
    /// Average number of reasons per stalled diagnostic.
    pub avg_reasons_per_stall: f64,
}

impl DiagnosticStats {
    /// Record a diagnostic result.
    fn record(&mut self, reasons: &[StallReason]) {
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
    }
}

// -----------------------------------------------------------------------------
// Stall reasons
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
    }
}

// -----------------------------------------------------------------------------
// Main diagnostic function
// -----------------------------------------------------------------------------

/// Analyze the current consensus state and return diagnostics.
///
/// # Arguments
/// * `state` — Current consensus state.
/// * `vset` — Validator set.
/// * `connected_validators` — Public keys of connected validators.
/// * `step_elapsed_ms` — Milliseconds since entering the current step.
/// * `propose_timeout_ms` — Proposal timeout in milliseconds.
/// * `config` — Diagnostic configuration.
/// * `stats` — Optional statistics accumulator.
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
    let mut reasons = Vec::new();
    let quorum_calc = QuorumCalculator::new(vset);

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
        };
        if let Some(s) = stats {
            s.record(&diag.stall_reasons);
        }
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
    let connected_val_count = vset
        .vals
        .iter()
        .filter(|v| connected_set.contains(&v.pk))
        .count();

    if connected_val_count == 0 && !vset.vals.is_empty() {
        reasons.push(StallReason::NoConnectedValidators {
            total_validators: vset.vals.len(),
        });
    } else if connected_val_count < vset.vals.len() {
        let needed = quorum_calc.quorum_threshold();
        if connected_val_count < needed {
            reasons.push(StallReason::InsufficientConnectedValidators {
                connected: connected_val_count,
                total: vset.vals.len(),
                needed,
            });
        }
    }

    // ── Step‑specific checks ────────────────────────────────────────────
    match state.step {
        Step::Propose => {
            if state.proposal.is_none() {
                let proposer = vset.proposer_for(state.height, state.round);
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

    let diag = ConsensusDiagnostic {
        height: state.height,
        round: state.round,
        step: format!("{:?}", state.step),
        stall_reasons: reasons,
        summary,
        is_healthy,
    };

    if let Some(s) = stats {
        s.record(&diag.stall_reasons);
    }

    diag
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

    // ── Basic scenario tests ────────────────────────────────────────────
    #[test]
    fn test_diagnose_committed() {
        let (vset, pks) = make_vset_and_pks(3);
        let mut state = ConsensusState::new(1);
        state.decided = Some(crate::consensus::engine::CommitCertificate {
            height: 1,
            block_id: crate::types::Hash32::zero(),
            precommits: vec![],
        });

        let diag = diagnose(&state, &vset, &pks, 0, TEST_PROPOSE_TIMEOUT_MS, &default_config(), None);
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
        let state = ConsensusState::new(1);

        let diag = diagnose(&state, &vset, &pks, 100, TEST_PROPOSE_TIMEOUT_MS, &default_config(), None);
        assert!(!diag.is_healthy);
        assert!(diag.summary.contains("waiting_proposal"));
    }

    #[test]
    fn test_diagnose_no_connected_validators() {
        let (vset, _pks) = make_vset_and_pks(3);
        let state = ConsensusState::new(1);

        let diag = diagnose(&state, &vset, &[], 100, TEST_PROPOSE_TIMEOUT_MS, &default_config(), None);
        assert!(!diag.is_healthy);
        assert!(
            diag.summary.contains("no_connected_validators")
                || diag.summary.contains("low_connectivity")
        );
    }

    #[test]
    fn test_diagnose_insufficient_connectivity() {
        let (vset, pks) = make_vset_and_pks(4);
        let state = ConsensusState::new(1);

        // Only 1 of 4 connected — not enough for quorum of 3.
        let diag = diagnose(&state, &vset, &pks[..1], 100, TEST_PROPOSE_TIMEOUT_MS, &default_config(), None);
        assert!(!diag.is_healthy);
        assert!(diag.summary.contains("low_connectivity"));
    }

    #[test]
    fn test_diagnose_ok_when_all_connected() {
        let (vset, pks) = make_vset_and_pks(3);
        let state = ConsensusState::new(1);

        let diag = diagnose(&state, &vset, &pks, 0, TEST_PROPOSE_TIMEOUT_MS, &default_config(), None);
        // All connected, but no proposal yet → waiting_proposal (not "OK").
        assert!(!diag.is_healthy);
        assert!(diag.summary.contains("waiting_proposal"));
    }

    #[test]
    fn test_diagnose_healthy_when_quorum_met() {
        let (vset, pks) = make_vset_and_pks(3);
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

        let diag = diagnose(&state, &vset, &pks, 0, TEST_PROPOSE_TIMEOUT_MS, &default_config(), None);
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
    }

    // ── Statistics tests ────────────────────────────────────────────────
    #[test]
    fn test_statistics_tracking() {
        let (vset, pks) = make_vset_and_pks(3);
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

        diagnose(&healthy_state, &vset, &pks, 0, TEST_PROPOSE_TIMEOUT_MS, &default_config(), Some(&mut stats));
        assert_eq!(stats.total_diagnostics, 1);
        assert_eq!(stats.healthy_count, 1);
        assert_eq!(stats.stalled_count, 0);

        // Run stalled diagnostic
        diagnose(&state, &vset, &[], 100, TEST_PROPOSE_TIMEOUT_MS, &default_config(), Some(&mut stats));
        assert_eq!(stats.total_diagnostics, 2);
        assert_eq!(stats.healthy_count, 1);
        assert_eq!(stats.stalled_count, 1);
        assert!(stats.reason_counts.values().sum::<u64>() > 0);
    }

    // ── Round advancement test ──────────────────────────────────────────
    #[test]
    fn test_diagnose_round_advancing() {
        let (vset, pks) = make_vset_and_pks(3);
        let mut state = ConsensusState::new(1);
        state.round = 15; // exceeds default max_rounds of 10

        let diag = diagnose(&state, &vset, &pks, 0, TEST_PROPOSE_TIMEOUT_MS, &default_config(), None);
        assert!(!diag.is_healthy);
        assert!(diag.summary.contains("round_advancing"));
    }

    // ── Reason truncation test ──────────────────────────────────────────
    #[test]
    fn test_max_reasons_truncation() {
        let (vset, _pks) = make_vset_and_pks(1);
        let mut state = ConsensusState::new(1);
        state.round = 20; // triggers round_advancing
        // No connected validators → triggers connectivity issues
        let config = DiagnosticConfig {
            max_reasons: 1,
            ..Default::default()
        };

        let diag = diagnose(&state, &vset, &[], 100, TEST_PROPOSE_TIMEOUT_MS, &config, None);
        assert_eq!(diag.stall_reasons.len(), 1);
    }

    // ── Serialization test ──────────────────────────────────────────────
    #[test]
    fn test_diagnostic_serialization() {
        let (vset, pks) = make_vset_and_pks(3);
        let state = ConsensusState::new(1);
        let diag = diagnose(&state, &vset, &pks, 100, TEST_PROPOSE_TIMEOUT_MS, &default_config(), None);

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
