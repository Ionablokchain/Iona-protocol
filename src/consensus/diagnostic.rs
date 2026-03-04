//! Consensus diagnostic module for IONA v28.
//!
//! When consensus stalls, this module provides a clear, single-line answer
//! to "why no commit?" instead of requiring you to read 5 different logs.
//!
//! Example output:
//!   NO_COMMIT height=42 round=0: missing_quorum have=2 need=3,
//!     validators_online=[val2,val3] missing=[val4],
//!     p2p_connected_validators=2/3

use crate::consensus::engine::{ConsensusState, Step};
use crate::consensus::quorum_diag::{QuorumCalculator, QuorumDiagnostic};
use crate::consensus::validator_set::ValidatorSet;
use crate::crypto::PublicKeyBytes;
use crate::types::{Hash32, Height, Round};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;

/// Possible reasons for consensus not committing.
#[derive(Debug, Clone, Serialize, Deserialize)]
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
    },
    /// Already committed at this height.
    AlreadyCommitted {
        height: Height,
    },
    /// Round is advancing (timeout-driven).
    RoundAdvancing {
        current_round: Round,
        max_rounds: u32,
    },
}

/// Full diagnostic snapshot.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConsensusDiagnostic {
    pub height: Height,
    pub round: Round,
    pub step: String,
    pub stall_reasons: Vec<StallReason>,
    /// One-line summary for quick logging.
    pub summary: String,
}

/// Analyze the current consensus state and return diagnostics.
pub fn diagnose(
    state: &ConsensusState,
    vset: &ValidatorSet,
    connected_validators: &[PublicKeyBytes],
    step_elapsed_ms: u64,
    propose_timeout_ms: u64,
) -> ConsensusDiagnostic {
    let mut reasons = Vec::new();
    let qc = QuorumCalculator::new(vset);

    // Check if already committed.
    if state.decided.is_some() {
        return ConsensusDiagnostic {
            height: state.height,
            round: state.round,
            step: format!("{:?}", state.step),
            stall_reasons: vec![StallReason::AlreadyCommitted { height: state.height }],
            summary: format!("COMMITTED height={}", state.height),
        };
    }

    // Check P2P connectivity to validators.
    let connected_set: HashSet<&PublicKeyBytes> = connected_validators.iter().collect();
    let connected_val_count = vset.vals.iter().filter(|v| connected_set.contains(&v.pk)).count();

    if connected_val_count == 0 && vset.vals.len() > 1 {
        reasons.push(StallReason::NoConnectedValidators {
            total_validators: vset.vals.len(),
        });
    } else if connected_val_count < vset.vals.len() {
        let needed = ((vset.vals.len() * 2) / 3) + 1;
        if connected_val_count < needed {
            reasons.push(StallReason::InsufficientConnectedValidators {
                connected: connected_val_count,
                total: vset.vals.len(),
                needed,
            });
        }
    }

    // Check based on current step.
    match state.step {
        Step::Propose => {
            if state.proposal.is_none() {
                let proposer = vset.proposer_for(state.height, state.round);
                reasons.push(StallReason::WaitingForProposal {
                    proposer: hex::encode(&proposer.pk.0[..8]),
                    elapsed_ms: step_elapsed_ms,
                    timeout_ms: propose_timeout_ms,
                });
            } else if state.proposal_block.is_none() {
                let block_id = state.proposal.as_ref()
                    .map(|p| hex::encode(&p.block_id.0[..8]))
                    .unwrap_or_default();
                reasons.push(StallReason::MissingBlock { block_id });
            }
        }
        Step::Prevote => {
            // Tally prevotes.
            let voters: Vec<PublicKeyBytes> = state.votes
                .get(&state.round)
                .and_then(|rv| rv.get(&crate::consensus::messages::VoteType::Prevote))
                .map(|m| m.keys().cloned().collect())
                .unwrap_or_default();
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
            let voters: Vec<PublicKeyBytes> = state.votes
                .get(&state.round)
                .and_then(|rv| rv.get(&crate::consensus::messages::VoteType::Precommit))
                .map(|m| m.keys().cloned().collect())
                .unwrap_or_default();
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
            // Should have been caught by decided check above.
        }
    }

    // Build summary.
    let summary = if reasons.is_empty() {
        format!("OK height={} round={} step={:?}", state.height, state.round, state.step)
    } else {
        let reason_strs: Vec<String> = reasons.iter().map(|r| match r {
            StallReason::WaitingForProposal { proposer, elapsed_ms, timeout_ms } =>
                format!("waiting_proposal(from={}, {}/{}ms)", proposer, elapsed_ms, timeout_ms),
            StallReason::MissingBlock { block_id } =>
                format!("missing_block(id={})", block_id),
            StallReason::InsufficientPrevotes { have, need, .. } =>
                format!("low_prevotes(have={} need={})", have, need),
            StallReason::InsufficientPrecommits { have, need, .. } =>
                format!("low_precommits(have={} need={})", have, need),
            StallReason::NoConnectedValidators { total_validators } =>
                format!("no_connected_validators(total={})", total_validators),
            StallReason::InsufficientConnectedValidators { connected, total, needed } =>
                format!("low_connectivity(connected={}/{} need={})", connected, total, needed),
            StallReason::AlreadyCommitted { height } =>
                format!("committed(height={})", height),
            StallReason::RoundAdvancing { current_round, max_rounds } =>
                format!("round_advancing({}/{})", current_round, max_rounds),
        }).collect();

        format!(
            "NO_COMMIT height={} round={} step={:?}: {}",
            state.height, state.round, state.step,
            reason_strs.join(", ")
        )
    };

    ConsensusDiagnostic {
        height: state.height,
        round: state.round,
        step: format!("{:?}", state.step),
        stall_reasons: reasons,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::consensus::validator_set::{Validator, ValidatorSet};
    use crate::crypto::Signer;
    use crate::crypto::ed25519::Ed25519Keypair;

    fn make_vset_and_pks(n: usize) -> (ValidatorSet, Vec<PublicKeyBytes>) {
        let mut vals = Vec::new();
        let mut pks = Vec::new();
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

    #[test]
    fn test_diagnose_committed() {
        let (vset, pks) = make_vset_and_pks(3);
        let mut state = ConsensusState::new(1);
        state.decided = Some(crate::consensus::engine::CommitCertificate {
            height: 1,
            block_id: Hash32::zero(),
            precommits: vec![],
        });

        let diag = diagnose(&state, &vset, &pks, 0, 300);
        assert!(diag.summary.contains("COMMITTED"));
    }

    #[test]
    fn test_diagnose_waiting_proposal() {
        let (vset, pks) = make_vset_and_pks(3);
        let state = ConsensusState::new(1);

        let diag = diagnose(&state, &vset, &pks, 100, 300);
        assert!(diag.summary.contains("waiting_proposal"));
    }

    #[test]
    fn test_diagnose_no_connected_validators() {
        let (vset, _pks) = make_vset_and_pks(3);
        let state = ConsensusState::new(1);

        let diag = diagnose(&state, &vset, &[], 100, 300);
        assert!(diag.summary.contains("no_connected_validators") || diag.summary.contains("low_connectivity"));
    }

    #[test]
    fn test_diagnose_insufficient_connectivity() {
        let (vset, pks) = make_vset_and_pks(4);
        let state = ConsensusState::new(1);

        // Only 1 of 4 connected — not enough for quorum of 3.
        let diag = diagnose(&state, &vset, &pks[..1], 100, 300);
        assert!(diag.summary.contains("low_connectivity"));
    }

    #[test]
    fn test_diagnose_ok_when_all_connected() {
        let (vset, pks) = make_vset_and_pks(3);
        let state = ConsensusState::new(1);

        // All connected, step=Propose, no proposal yet → waiting_proposal.
        let diag = diagnose(&state, &vset, &pks, 0, 300);
        // This will show waiting_proposal, not connectivity issues.
        assert!(!diag.summary.contains("low_connectivity"));
        assert!(!diag.summary.contains("no_connected"));
    }
}
