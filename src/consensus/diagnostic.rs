//! Consensus diagnostic module for IONA.
//!
//! When consensus stalls, this module provides a clear, single-line answer
//! to "why no commit?" without requiring operators to correlate multiple logs.

use crate::consensus::engine::{ConsensusState, Step};
use crate::consensus::messages::VoteType;
use crate::consensus::quorum_diag::QuorumCalculator;
use crate::consensus::validator_set::ValidatorSet;
use crate::crypto::PublicKeyBytes;
use crate::types::{Height, Round};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;

/// Possible reasons for consensus not committing.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "reason")]
pub enum StallReason {
    /// Validator set is empty or unavailable.
    EmptyValidatorSet,

    /// Waiting for proposal from the designated proposer.
    WaitingForProposal {
        proposer: String,
        elapsed_ms: u64,
        timeout_ms: u64,
    },

    /// Proposal received but full block not yet available.
    MissingBlock {
        block_id: String,
    },

    /// Not enough prevotes to proceed.
    InsufficientPrevotes {
        have: u64,
        need: u64,
        voted: Vec<String>,
        missing: Vec<String>,
    },

    /// Not enough precommits to commit.
    InsufficientPrecommits {
        have: u64,
        need: u64,
        voted: Vec<String>,
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
        connected_validators: Vec<String>,
        missing_validators: Vec<String>,
    },

    /// Already committed at this height.
    AlreadyCommitted {
        height: Height,
    },

    /// Round is advancing due to timeouts / retries.
    RoundAdvancing {
        current_round: Round,
        previous_round: Round,
    },

    /// We have enough votes/connectivity and should not be stalled.
    NoObviousStall,
}

/// Full diagnostic snapshot.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConsensusDiagnostic {
    pub height: Height,
    pub round: Round,
    pub step: String,
    pub stall_reasons: Vec<StallReason>,
    /// One-line summary for quick logging.
    pub summary: String,
}

impl ConsensusDiagnostic {
    pub fn is_stalled(&self) -> bool {
        !self.stall_reasons.is_empty()
            && !self
                .stall_reasons
                .iter()
                .all(|r| matches!(r, StallReason::AlreadyCommitted { .. } | StallReason::NoObviousStall))
    }
}

/// Optional knobs for diagnostics.
#[derive(Debug, Clone, Copy)]
pub struct DiagnosticCfg {
    /// Proposal timeout in ms for human-readable output.
    pub propose_timeout_ms: u64,
    /// Previous round, if tracked by caller, for round-advance diagnostics.
    pub previous_round: Option<Round>,
}

impl Default for DiagnosticCfg {
    fn default() -> Self {
        Self {
            propose_timeout_ms: 3000,
            previous_round: None,
        }
    }
}

/// Analyze the current consensus state and return diagnostics.
pub fn diagnose(
    state: &ConsensusState,
    vset: &ValidatorSet,
    connected_validators: &[PublicKeyBytes],
    step_elapsed_ms: u64,
    cfg: DiagnosticCfg,
) -> ConsensusDiagnostic {
    let mut reasons = Vec::new();

    if vset.vals.is_empty() {
        reasons.push(StallReason::EmptyValidatorSet);
        return finalize(state, reasons);
    }

    if state.decided.is_some() {
        reasons.push(StallReason::AlreadyCommitted {
            height: state.height,
        });
        return finalize(state, reasons);
    }

    if let Some(prev_round) = cfg.previous_round {
        if state.round > prev_round {
            reasons.push(StallReason::RoundAdvancing {
                current_round: state.round,
                previous_round: prev_round,
            });
        }
    }

    let qc = QuorumCalculator::new(vset);

    let connectivity = analyze_connectivity(vset, connected_validators);
    match connectivity {
        ConnectivityDiagnostic::NoneConnected { total } if total > 1 => {
            reasons.push(StallReason::NoConnectedValidators {
                total_validators: total,
            });
        }
        ConnectivityDiagnostic::Insufficient {
            connected,
            total,
            needed,
            connected_validators,
            missing_validators,
        } => {
            reasons.push(StallReason::InsufficientConnectedValidators {
                connected,
                total,
                needed,
                connected_validators,
                missing_validators,
            });
        }
        ConnectivityDiagnostic::Sufficient { .. } | ConnectivityDiagnostic::NoneConnected { .. } => {}
    }

    match state.step {
        Step::Propose => {
            if state.proposal.is_none() {
                let proposer = vset.proposer_for(state.height, state.round);
                reasons.push(StallReason::WaitingForProposal {
                    proposer: short_pk(&proposer.pk),
                    elapsed_ms: step_elapsed_ms,
                    timeout_ms: cfg.propose_timeout_ms,
                });
            } else if state.proposal_block.is_none() {
                let block_id = state
                    .proposal
                    .as_ref()
                    .map(|p| short_hash_bytes(&p.block_id.0))
                    .unwrap_or_default();

                reasons.push(StallReason::MissingBlock { block_id });
            }
        }

        Step::Prevote => {
            let voters = collect_voters(state, state.round, VoteType::Prevote);
            let diag = qc.check(&voters);

            if !diag.has_quorum {
                reasons.push(StallReason::InsufficientPrevotes {
                    have: diag.current_power,
                    need: diag.quorum_threshold,
                    voted: diag.voted,
                    missing: diag.missing,
                });
            }
        }

        Step::Precommit => {
            let voters = collect_voters(state, state.round, VoteType::Precommit);
            let diag = qc.check(&voters);

            if !diag.has_quorum {
                reasons.push(StallReason::InsufficientPrecommits {
                    have: diag.current_power,
                    need: diag.quorum_threshold,
                    voted: diag.voted,
                    missing: diag.missing,
                });
            }
        }

        Step::Commit => {
            if reasons.is_empty() {
                reasons.push(StallReason::NoObviousStall);
            }
        }
    }

    if reasons.is_empty() {
        reasons.push(StallReason::NoObviousStall);
    }

    finalize(state, reasons)
}

/// Build a final diagnostic with consistent summary formatting.
fn finalize(state: &ConsensusState, stall_reasons: Vec<StallReason>) -> ConsensusDiagnostic {
    let summary = build_summary(state, &stall_reasons);

    ConsensusDiagnostic {
        height: state.height,
        round: state.round,
        step: format!("{:?}", state.step),
        stall_reasons,
        summary,
    }
}

fn build_summary(state: &ConsensusState, reasons: &[StallReason]) -> String {
    if reasons.is_empty() {
        return format!(
            "OK height={} round={} step={:?}",
            state.height, state.round, state.step
        );
    }

    if reasons.len() == 1 {
        if let StallReason::AlreadyCommitted { height } = reasons[0] {
            return format!("COMMITTED height={height}");
        }
    }

    if reasons.iter().all(|r| matches!(r, StallReason::NoObviousStall)) {
        return format!(
            "OK height={} round={} step={:?}",
            state.height, state.round, state.step
        );
    }

    let items: Vec<String> = reasons.iter().map(format_reason).collect();

    format!(
        "NO_COMMIT height={} round={} step={:?}: {}",
        state.height,
        state.round,
        state.step,
        items.join(", ")
    )
}

fn format_reason(reason: &StallReason) -> String {
    match reason {
        StallReason::EmptyValidatorSet => "empty_validator_set".to_string(),

        StallReason::WaitingForProposal {
            proposer,
            elapsed_ms,
            timeout_ms,
        } => format!(
            "waiting_proposal(from={} elapsed={}ms timeout={}ms)",
            proposer, elapsed_ms, timeout_ms
        ),

        StallReason::MissingBlock { block_id } => {
            format!("missing_block(id={})", block_id)
        }

        StallReason::InsufficientPrevotes { have, need, voted, missing } => format!(
            "low_prevotes(have={} need={} voted=[{}] missing=[{}])",
            have,
            need,
            voted.join(","),
            missing.join(",")
        ),

        StallReason::InsufficientPrecommits {
            have,
            need,
            voted,
            missing,
        } => format!(
            "low_precommits(have={} need={} voted=[{}] missing=[{}])",
            have,
            need,
            voted.join(","),
            missing.join(",")
        ),

        StallReason::NoConnectedValidators { total_validators } => {
            format!("no_connected_validators(total={})", total_validators)
        }

        StallReason::InsufficientConnectedValidators {
            connected,
            total,
            needed,
            connected_validators,
            missing_validators,
        } => format!(
            "low_connectivity(connected={}/{} need={} connected_validators=[{}] missing=[{}])",
            connected,
            total,
            needed,
            connected_validators.join(","),
            missing_validators.join(",")
        ),

        StallReason::AlreadyCommitted { height } => {
            format!("committed(height={})", height)
        }

        StallReason::RoundAdvancing {
            current_round,
            previous_round,
        } => format!(
            "round_advancing(prev_round={} current_round={})",
            previous_round, current_round
        ),

        StallReason::NoObviousStall => "no_obvious_stall".to_string(),
    }
}

fn collect_voters(state: &ConsensusState, round: Round, vote_type: VoteType) -> Vec<PublicKeyBytes> {
    state
        .votes
        .get(&round)
        .and_then(|rv| rv.get(&vote_type))
        .map(|m| m.keys().cloned().collect())
        .unwrap_or_default()
}

fn short_pk(pk: &PublicKeyBytes) -> String {
    short_hash_bytes(&pk.0)
}

fn short_hash_bytes(bytes: &[u8]) -> String {
    let n = bytes.len().min(8);
    hex::encode(&bytes[..n])
}

enum ConnectivityDiagnostic {
    NoneConnected {
        total: usize,
    },
    Insufficient {
        connected: usize,
        total: usize,
        needed: usize,
        connected_validators: Vec<String>,
        missing_validators: Vec<String>,
    },
    Sufficient {
        connected: usize,
        total: usize,
        needed: usize,
        connected_validators: Vec<String>,
        missing_validators: Vec<String>,
    },
}

fn analyze_connectivity(
    vset: &ValidatorSet,
    connected_validators: &[PublicKeyBytes],
) -> ConnectivityDiagnostic {
    let connected_set: HashSet<&PublicKeyBytes> = connected_validators.iter().collect();

    let mut connected_names = Vec::new();
    let mut missing_names = Vec::new();

    for val in &vset.vals {
        if connected_set.contains(&val.pk) {
            connected_names.push(short_pk(&val.pk));
        } else {
            missing_names.push(short_pk(&val.pk));
        }
    }

    let connected = connected_names.len();
    let total = vset.vals.len();
    let needed = quorum_threshold(total);

    if connected == 0 {
        return ConnectivityDiagnostic::NoneConnected { total };
    }

    if connected < needed {
        return ConnectivityDiagnostic::Insufficient {
            connected,
            total,
            needed,
            connected_validators: connected_names,
            missing_validators: missing_names,
        };
    }

    ConnectivityDiagnostic::Sufficient {
        connected,
        total,
        needed,
        connected_validators: connected_names,
        missing_validators: missing_names,
    }
}

fn quorum_threshold(n: usize) -> usize {
    ((n * 2) / 3) + 1
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::consensus::engine::CommitCertificate;
    use crate::consensus::validator_set::{Validator, ValidatorSet};
    use crate::crypto::ed25519::Ed25519Keypair;
    use crate::crypto::Signer;
    use crate::types::Hash32;

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

    #[test]
    fn test_diagnose_committed() {
        let (vset, pks) = make_vset_and_pks(3);
        let mut state = ConsensusState::new(1);
        state.decided = Some(CommitCertificate {
            height: 1,
            block_id: Hash32::zero(),
            precommits: vec![],
        });

        let diag = diagnose(
            &state,
            &vset,
            &pks,
            0,
            DiagnosticCfg {
                propose_timeout_ms: 300,
                previous_round: None,
            },
        );

        assert_eq!(diag.height, 1);
        assert!(diag.summary.contains("COMMITTED"));
        assert!(matches!(
            diag.stall_reasons.first(),
            Some(StallReason::AlreadyCommitted { .. })
        ));
    }

    #[test]
    fn test_diagnose_empty_validator_set() {
        let vset = ValidatorSet { vals: vec![] };
        let state = ConsensusState::new(1);

        let diag = diagnose(&state, &vset, &[], 0, DiagnosticCfg::default());

        assert!(diag.summary.contains("empty_validator_set"));
        assert!(matches!(
            diag.stall_reasons.first(),
            Some(StallReason::EmptyValidatorSet)
        ));
    }

    #[test]
    fn test_diagnose_waiting_proposal() {
        let (vset, pks) = make_vset_and_pks(3);
        let state = ConsensusState::new(1);

        let diag = diagnose(
            &state,
            &vset,
            &pks,
            100,
            DiagnosticCfg {
                propose_timeout_ms: 300,
                previous_round: None,
            },
        );

        assert!(diag.summary.contains("waiting_proposal"));
    }

    #[test]
    fn test_diagnose_no_connected_validators() {
        let (vset, _) = make_vset_and_pks(3);
        let state = ConsensusState::new(1);

        let diag = diagnose(&state, &vset, &[], 100, DiagnosticCfg::default());

        assert!(
            diag.summary.contains("no_connected_validators")
                || diag.summary.contains("low_connectivity")
        );
    }

    #[test]
    fn test_diagnose_insufficient_connectivity() {
        let (vset, pks) = make_vset_and_pks(4);
        let state = ConsensusState::new(1);

        let diag = diagnose(&state, &vset, &pks[..1], 100, DiagnosticCfg::default());

        assert!(diag.summary.contains("low_connectivity"));
    }

    #[test]
    fn test_diagnose_ok_when_all_connected_but_waiting_proposal() {
        let (vset, pks) = make_vset_and_pks(3);
        let state = ConsensusState::new(1);

        let diag = diagnose(&state, &vset, &pks, 0, DiagnosticCfg::default());

        assert!(!diag.summary.contains("low_connectivity"));
        assert!(!diag.summary.contains("no_connected"));
        assert!(diag.summary.contains("waiting_proposal"));
    }

    #[test]
    fn test_round_advancing_is_reported() {
        let (vset, pks) = make_vset_and_pks(3);
        let mut state = ConsensusState::new(1);
        state.round = 2;

        let diag = diagnose(
            &state,
            &vset,
            &pks,
            50,
            DiagnosticCfg {
                propose_timeout_ms: 300,
                previous_round: Some(1),
            },
        );

        assert!(diag.summary.contains("round_advancing"));
    }

    #[test]
    fn test_quorum_threshold_helper() {
        assert_eq!(quorum_threshold(1), 1);
        assert_eq!(quorum_threshold(2), 2);
        assert_eq!(quorum_threshold(3), 3);
        assert_eq!(quorum_threshold(4), 3);
        assert_eq!(quorum_threshold(10), 7);
    }
}
