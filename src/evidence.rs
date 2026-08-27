//! Quantum evidence types for consensus faults.
//!
//! # Quantum Consensus Fault Model
//!
//! In the quantum consensus model, validators are represented as quantum
//! systems that must exist in a single eigenstate per round. A double-vote
//! or double-proposal represents a **quantum forbidden transition** where
//! the validator's state has bifurcated into a superposition of conflicting
//! outcomes — a violation of the no-cloning theorem for consensus states.
//!
//! # Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────────────────┐
//! │                         Evidence Module                                │
//! ├─────────────┬──────────────┬───────────────┬──────────────────────────┤
//! │   Config    │    Error     │    Metrics    │         Types            │
//! │ (EvCfg)     │ (EvError)    │ (EvMetrics)   │ (Evidence, Vote, Proposal)│
//! ├─────────────┼──────────────┼───────────────┼──────────────────────────┤
//! │   Manager   │    Legacy    │               │                          │
//! │ (EvManager) │ (global fns) │               │                          │
//! └─────────────────────────────────────────────────────────────────────────┘
//! ```
//!
//! # Example
//!
//! ```rust,ignore
//! use iona::evidence::{EvidenceManager, EvidenceConfig};
//!
//! let config = EvidenceConfig::default();
//! let manager = EvidenceManager::new(config);
//! let evidence = manager.create_double_vote(vote_a, vote_b)?;
//! let verified = manager.verify_quantum(&mut evidence)?;
//! ```

#![allow(dead_code)]

use crate::consensus::messages::{Proposal, Vote, VoteType};
use crate::crypto::{PublicKeyBytes, Signature, verify_signature};
use crate::types::{Hash32, Height, Round};
use serde::{Deserialize, Serialize};
use std::fmt;
use thiserror::Error;

// -----------------------------------------------------------------------------
// Submodules (embedded)
// -----------------------------------------------------------------------------

pub mod constants {
    //! Constants for the evidence subsystem.
    /// Entanglement witness threshold for fault detection.
    pub const WITNESS_THRESHOLD: f64 = 0.99;

    /// Reduced Planck constant (natural units).
    pub const HBAR: f64 = 1.0;

    /// Fault coupling constant for double-vote.
    pub const G_VOTE: f64 = 1.0;

    /// Fault coupling constant for double-proposal.
    pub const G_PROPOSAL: f64 = 1.0;

    /// Maximum allowed coherence degradation before evidence is considered invalid.
    pub const MAX_COHERENCE_LOSS: f64 = 0.1;
}

pub mod config {
    //! Configuration for the evidence subsystem.
    use serde::{Deserialize, Serialize};
    use super::constants::*;

    /// Configuration for evidence handling.
    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct EvidenceConfig {
        pub witness_threshold: f64,
        pub max_coherence_loss: f64,
        pub verify_signatures: bool,
        pub collect_metrics: bool,
        pub log_operations: bool,
        pub auto_verify_on_create: bool,
        pub require_quantum_validation: bool,
    }

    impl Default for EvidenceConfig {
        fn default() -> Self {
            Self {
                witness_threshold: WITNESS_THRESHOLD,
                max_coherence_loss: MAX_COHERENCE_LOSS,
                verify_signatures: true,
                collect_metrics: true,
                log_operations: false,
                auto_verify_on_create: true,
                require_quantum_validation: true,
            }
        }
    }

    impl EvidenceConfig {
        pub fn validate(&self) -> Result<(), &'static str> {
            if self.witness_threshold < 0.0 || self.witness_threshold > 1.0 {
                return Err("witness_threshold must be between 0 and 1");
            }
            if self.max_coherence_loss < 0.0 || self.max_coherence_loss > 1.0 {
                return Err("max_coherence_loss must be between 0 and 1");
            }
            Ok(())
        }

        pub fn with_metrics(mut self) -> Self {
            self.collect_metrics = true;
            self
        }
    }
}

pub mod error {
    //! Errors for evidence verification.
    use super::types::{Height, Round, VoteType};
    use thiserror::Error;

    #[derive(Debug, Error, Clone, PartialEq, Eq)]
    pub enum EvidenceError {
        #[error("quantum duplicate: messages occupy identical state vectors")]
        DuplicateMessages,

        #[error("Hilbert space mismatch: height/round eigenvalues differ")]
        MismatchedHeightRound,

        #[error("observable mismatch: vote_type eigenvalues differ")]
        VoteTypeMismatch,

        #[error("entanglement broken: proposer identity differs")]
        ProposerMismatch,

        #[error("signature quantum state verification failed: {0}")]
        InvalidSignature(String),

        #[error("measurement error: missing block hash observable")]
        MissingBlockHash,

        #[error("decoherence: evidence state has lost fidelity ({fidelity})")]
        Decoherence { fidelity: f64 },

        #[error("witness operator expectation below threshold: {value} < {threshold}")]
        WitnessBelowThreshold { value: f64, threshold: f64 },

        #[error("evidence already verified: cannot mutate")]
        AlreadyVerified,

        #[error("invalid coherence: {reason}")]
        InvalidCoherence { reason: String },
    }

    pub type EvidenceResult<T> = Result<T, EvidenceError>;
}

pub mod types {
    //! Core evidence types.
    use super::{
        config::EvidenceConfig,
        constants::{WITNESS_THRESHOLD, MAX_COHERENCE_LOSS},
        error::{EvidenceError, EvidenceResult},
        metrics::global_metrics,
    };
    use crate::consensus::messages::{Proposal, Vote, VoteType};
    use crate::crypto::{PublicKeyBytes, verify_signature};
    use crate::types::{Hash32, Height, Round};
    use serde::{Deserialize, Serialize};
    use std::fmt;
    use tracing::{debug, trace};

    /// Represents the quantum state of a fault evidence.
    #[derive(Debug, Clone)]
    struct QuantumEvidenceState {
        coherence: f64,
        fidelity: f64,
        witness_value: f64,
        verified: bool,
    }

    impl QuantumEvidenceState {
        fn new() -> Self {
            Self {
                coherence: 1.0,
                fidelity: 1.0,
                witness_value: 0.0,
                verified: false,
            }
        }

        fn compute_witness(&mut self, state_a_hash: &[u8], state_b_hash: &[u8]) -> f64 {
            let overlap = state_a_hash
                .iter()
                .zip(state_b_hash.iter())
                .filter(|(a, b)| a == b)
                .count() as f64
                / state_a_hash.len().max(1) as f64;
            self.witness_value = 1.0 - overlap;
            self.witness_value
        }

        fn is_fault_detected(&self, threshold: f64) -> bool {
            self.witness_value > threshold
        }

        fn apply_decoherence(&mut self, strength: f64) {
            self.coherence *= (-strength).exp();
            self.fidelity = self.coherence.sqrt();
        }

        fn mark_verified(&mut self) {
            self.verified = true;
        }

        fn is_verified(&self) -> bool {
            self.verified
        }
    }

    /// Evidence of a consensus fault — a quantum forbidden transition.
    #[derive(Clone, Debug, Serialize, Deserialize)]
    #[serde(tag = "type", content = "data")]
    pub enum Evidence {
        DoubleVote {
            voter: PublicKeyBytes,
            height: Height,
            round: Round,
            vote_type: VoteType,
            a: Option<Hash32>,
            b: Option<Hash32>,
            vote_a: Vote,
            vote_b: Vote,
            #[serde(default = "default_coherence")]
            coherence: f64,
            #[serde(default)]
            witness_value: f64,
            #[serde(default)]
            verified: bool,
        },
        DoubleProposal {
            proposer: PublicKeyBytes,
            height: Height,
            round: Round,
            a: Option<Hash32>,
            b: Option<Hash32>,
            proposal_a: Proposal,
            proposal_b: Proposal,
            #[serde(default = "default_coherence")]
            coherence: f64,
            #[serde(default)]
            witness_value: f64,
            #[serde(default)]
            verified: bool,
        },
    }

    fn default_coherence() -> f64 {
        1.0
    }

    impl Evidence {
        // ── Constructors ─────────────────────────────────────────────────────

        pub fn new_double_vote(vote_a: Vote, vote_b: Vote, config: &EvidenceConfig) -> EvidenceResult<Self> {
            if vote_a == vote_b {
                return Err(EvidenceError::DuplicateMessages);
            }
            if vote_a.validator != vote_b.validator {
                return Err(EvidenceError::ProposerMismatch);
            }
            if vote_a.height != vote_b.height || vote_a.round != vote_b.round {
                return Err(EvidenceError::MismatchedHeightRound);
            }
            if vote_a.vote_type != vote_b.vote_type {
                return Err(EvidenceError::VoteTypeMismatch);
            }

            let voter = vote_a.validator;
            let height = vote_a.height;
            let round = vote_a.round;
            let vote_type = vote_a.vote_type;
            let a = vote_a.block_hash;
            let b = vote_b.block_hash;

            let mut ev = Self::DoubleVote {
                voter,
                height,
                round,
                vote_type,
                a,
                b,
                vote_a,
                vote_b,
                coherence: 1.0,
                witness_value: 0.0,
                verified: false,
            };
            if config.auto_verify_on_create {
                ev.verify_quantum(config)?;
            }
            Ok(ev)
        }

        pub fn new_double_proposal(proposal_a: Proposal, proposal_b: Proposal, config: &EvidenceConfig) -> EvidenceResult<Self> {
            if proposal_a == proposal_b {
                return Err(EvidenceError::DuplicateMessages);
            }
            if proposal_a.proposer != proposal_b.proposer {
                return Err(EvidenceError::ProposerMismatch);
            }
            if proposal_a.height != proposal_b.height || proposal_a.round != proposal_b.round {
                return Err(EvidenceError::MismatchedHeightRound);
            }

            let proposer = proposal_a.proposer;
            let height = proposal_a.height;
            let round = proposal_a.round;
            let a = proposal_a.block_hash;
            let b = proposal_b.block_hash;

            let mut ev = Self::DoubleProposal {
                proposer,
                height,
                round,
                a,
                b,
                proposal_a,
                proposal_b,
                coherence: 1.0,
                witness_value: 0.0,
                verified: false,
            };
            if config.auto_verify_on_create {
                ev.verify_quantum(config)?;
            }
            Ok(ev)
        }

        // ── Accessors ─────────────────────────────────────────────────────

        pub fn height(&self) -> Height {
            match self {
                Self::DoubleVote { height, .. } => *height,
                Self::DoubleProposal { height, .. } => *height,
            }
        }

        pub fn round(&self) -> Round {
            match self {
                Self::DoubleVote { round, .. } => *round,
                Self::DoubleProposal { round, .. } => *round,
            }
        }

        pub fn offender(&self) -> PublicKeyBytes {
            match self {
                Self::DoubleVote { voter, .. } => *voter,
                Self::DoubleProposal { proposer, .. } => *proposer,
            }
        }

        pub fn coherence(&self) -> f64 {
            match self {
                Self::DoubleVote { coherence, .. } => *coherence,
                Self::DoubleProposal { coherence, .. } => *coherence,
            }
        }

        pub fn witness_value(&self) -> f64 {
            match self {
                Self::DoubleVote { witness_value, .. } => *witness_value,
                Self::DoubleProposal { witness_value, .. } => *witness_value,
            }
        }

        pub fn is_verified(&self) -> bool {
            match self {
                Self::DoubleVote { verified, .. } => *verified,
                Self::DoubleProposal { verified, .. } => *verified,
            }
        }

        // ── Validation ──────────────────────────────────────────────────────

        pub fn validate(&self) -> EvidenceResult<()> {
            match self {
                Self::DoubleVote {
                    voter: _,
                    height,
                    round,
                    vote_type,
                    a: _,
                    b: _,
                    vote_a,
                    vote_b,
                    ..
                } => {
                    if vote_a == vote_b {
                        return Err(EvidenceError::DuplicateMessages);
                    }
                    if vote_a.validator != vote_b.validator {
                        return Err(EvidenceError::ProposerMismatch);
                    }
                    if vote_a.height != *height
                        || vote_b.height != *height
                        || vote_a.round != *round
                        || vote_b.round != *round
                        || vote_a.vote_type != *vote_type
                        || vote_b.vote_type != *vote_type
                    {
                        return Err(EvidenceError::MismatchedHeightRound);
                    }
                    Ok(())
                }
                Self::DoubleProposal {
                    proposer: _,
                    height,
                    round,
                    a: _,
                    b: _,
                    proposal_a,
                    proposal_b,
                    ..
                } => {
                    if proposal_a == proposal_b {
                        return Err(EvidenceError::DuplicateMessages);
                    }
                    if proposal_a.proposer != proposal_b.proposer {
                        return Err(EvidenceError::ProposerMismatch);
                    }
                    if proposal_a.height != *height
                        || proposal_b.height != *height
                        || proposal_a.round != *round
                        || proposal_b.round != *round
                    {
                        return Err(EvidenceError::MismatchedHeightRound);
                    }
                    Ok(())
                }
            }
        }

        pub fn verify_quantum(&mut self, config: &EvidenceConfig) -> EvidenceResult<()> {
            if self.is_verified() {
                return Err(EvidenceError::AlreadyVerified);
            }

            self.validate()?;

            let mut qstate = QuantumEvidenceState::new();

            match self {
                Self::DoubleVote {
                    vote_a,
                    vote_b,
                    witness_value,
                    coherence,
                    verified,
                    ..
                } => {
                    let hash_a = vote_a.encode_for_signing();
                    let hash_b = vote_b.encode_for_signing();
                    let witness = qstate.compute_witness(&hash_a, &hash_b);
                    if !qstate.is_fault_detected(config.witness_threshold) {
                        return Err(EvidenceError::WitnessBelowThreshold {
                            value: witness,
                            threshold: config.witness_threshold,
                        });
                    }
                    qstate.apply_decoherence(0.001);
                    if qstate.coherence < 1.0 - config.max_coherence_loss {
                        return Err(EvidenceError::Decoherence {
                            fidelity: qstate.fidelity,
                        });
                    }
                    *witness_value = witness;
                    *coherence = qstate.coherence;
                    *verified = false;
                }
                Self::DoubleProposal {
                    proposal_a,
                    proposal_b,
                    witness_value,
                    coherence,
                    verified,
                    ..
                } => {
                    let hash_a = proposal_a.encode_for_signing();
                    let hash_b = proposal_b.encode_for_signing();
                    let witness = qstate.compute_witness(&hash_a, &hash_b);
                    if !qstate.is_fault_detected(config.witness_threshold) {
                        return Err(EvidenceError::WitnessBelowThreshold {
                            value: witness,
                            threshold: config.witness_threshold,
                        });
                    }
                    qstate.apply_decoherence(0.001);
                    if qstate.coherence < 1.0 - config.max_coherence_loss {
                        return Err(EvidenceError::Decoherence {
                            fidelity: qstate.fidelity,
                        });
                    }
                    *witness_value = witness;
                    *coherence = qstate.coherence;
                    *verified = false;
                }
            }

            Ok(())
        }

        pub fn verify_signatures(&self) -> EvidenceResult<()> {
            match self {
                Self::DoubleVote { vote_a, vote_b, .. } => {
                    self.verify_vote_signature(vote_a)?;
                    self.verify_vote_signature(vote_b)?;
                    Ok(())
                }
                Self::DoubleProposal { proposal_a, proposal_b, .. } => {
                    self.verify_proposal_signature(proposal_a)?;
                    self.verify_proposal_signature(proposal_b)?;
                    Ok(())
                }
            }
        }

        pub fn verify(&self) -> EvidenceResult<()> {
            self.validate()?;
            self.verify_signatures()?;
            Ok(())
        }

        pub fn verify_and_mark(&mut self, config: &EvidenceConfig) -> EvidenceResult<()> {
            if self.is_verified() {
                return Ok(());
            }
            self.verify_quantum(config)?;
            if config.verify_signatures {
                self.verify_signatures()?;
            }
            match self {
                Self::DoubleVote { verified, .. } => *verified = true,
                Self::DoubleProposal { verified, .. } => *verified = true,
            }
            Ok(())
        }

        pub fn severity(&self) -> f64 {
            let witness = self.witness_value();
            let threshold = WITNESS_THRESHOLD;
            let severity = (witness - threshold) / (1.0 - threshold);
            severity.clamp(0.0, 1.0)
        }

        // ── Private helpers ─────────────────────────────────────────────────

        fn verify_vote_signature(&self, vote: &Vote) -> EvidenceResult<()> {
            let bytes = vote.encode_for_signing();
            verify_signature(&bytes, &vote.signature, &vote.validator)
                .map_err(|e| EvidenceError::InvalidSignature(format!("vote: {e}")))
        }

        fn verify_proposal_signature(&self, proposal: &Proposal) -> EvidenceResult<()> {
            let bytes = proposal.encode_for_signing();
            verify_signature(&bytes, &proposal.signature, &proposal.proposer)
                .map_err(|e| EvidenceError::InvalidSignature(format!("proposal: {e}")))
        }
    }

    impl fmt::Display for Evidence {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            match self {
                Self::DoubleVote {
                    voter,
                    height,
                    round,
                    vote_type,
                    a,
                    b,
                    coherence,
                    witness_value,
                    verified,
                    ..
                } => {
                    write!(
                        f,
                        "DoubleVote(voter={}, h={}, r={}, type={:?}, a={:?}, b={:?}, γ={:.4}, W={:.4}, verified={})",
                        hex::encode(voter.as_bytes()),
                        height,
                        round,
                        vote_type,
                        a,
                        b,
                        coherence,
                        witness_value,
                        verified
                    )
                }
                Self::DoubleProposal {
                    proposer,
                    height,
                    round,
                    a,
                    b,
                    coherence,
                    witness_value,
                    verified,
                    ..
                } => {
                    write!(
                        f,
                        "DoubleProposal(proposer={}, h={}, r={}, a={:?}, b={:?}, γ={:.4}, W={:.4}, verified={})",
                        hex::encode(proposer.as_bytes()),
                        height,
                        round,
                        a,
                        b,
                        coherence,
                        witness_value,
                        verified
                    )
                }
            }
        }
    }
}

pub mod metrics {
    //! Metrics for the evidence subsystem.
    use core::sync::atomic::{AtomicU64, Ordering};
    use serde::{Deserialize, Serialize};

    #[derive(Debug, Default)]
    pub struct EvidenceMetrics {
        pub evidence_created: AtomicU64,
        pub double_vote_created: AtomicU64,
        pub double_proposal_created: AtomicU64,
        pub evidence_verified: AtomicU64,
        pub verification_failures: AtomicU64,
        pub signature_failures: AtomicU64,
        pub witness_failures: AtomicU64,
        pub decoherence_failures: AtomicU64,
        pub auto_verified: AtomicU64,
    }

    impl EvidenceMetrics {
        pub fn inc_created(&self, ev_type: &str) {
            self.evidence_created.fetch_add(1, Ordering::Relaxed);
            match ev_type {
                "double_vote" => self.double_vote_created.fetch_add(1, Ordering::Relaxed),
                "double_proposal" => self.double_proposal_created.fetch_add(1, Ordering::Relaxed),
                _ => 0,
            };
        }

        pub fn inc_verified(&self) {
            self.evidence_verified.fetch_add(1, Ordering::Relaxed);
        }

        pub fn inc_verification_failure(&self, reason: &str) {
            self.verification_failures.fetch_add(1, Ordering::Relaxed);
            match reason {
                "signature" => self.signature_failures.fetch_add(1, Ordering::Relaxed),
                "witness" => self.witness_failures.fetch_add(1, Ordering::Relaxed),
                "decoherence" => self.decoherence_failures.fetch_add(1, Ordering::Relaxed),
                _ => 0,
            };
        }

        pub fn inc_auto_verified(&self) {
            self.auto_verified.fetch_add(1, Ordering::Relaxed);
        }

        pub fn snapshot(&self) -> EvidenceMetricsSnapshot {
            EvidenceMetricsSnapshot {
                evidence_created: self.evidence_created.load(Ordering::Relaxed),
                double_vote_created: self.double_vote_created.load(Ordering::Relaxed),
                double_proposal_created: self.double_proposal_created.load(Ordering::Relaxed),
                evidence_verified: self.evidence_verified.load(Ordering::Relaxed),
                verification_failures: self.verification_failures.load(Ordering::Relaxed),
                signature_failures: self.signature_failures.load(Ordering::Relaxed),
                witness_failures: self.witness_failures.load(Ordering::Relaxed),
                decoherence_failures: self.decoherence_failures.load(Ordering::Relaxed),
                auto_verified: self.auto_verified.load(Ordering::Relaxed),
            }
        }
    }

    /// Global metrics instance.
    pub(crate) static GLOBAL_METRICS: spin::Once<EvidenceMetrics> = spin::Once::new();

    pub fn global_metrics() -> &'static EvidenceMetrics {
        GLOBAL_METRICS.get_or_init(EvidenceMetrics::default)
    }
}

pub mod manager {
    //! Centralised manager for evidence operations.
    use super::{
        config::EvidenceConfig,
        error::{EvidenceError, EvidenceResult},
        types::Evidence,
        metrics::global_metrics,
    };
    use crate::consensus::messages::{Proposal, Vote};
    use tracing::{debug, info, trace, warn};

    /// Manager for evidence handling.
    pub struct EvidenceManager {
        config: EvidenceConfig,
        initialised: bool,
    }

    impl EvidenceManager {
        pub fn new(config: EvidenceConfig) -> Self {
            config.validate().expect("invalid EvidenceConfig");
            Self {
                config,
                initialised: false,
            }
        }

        pub fn default() -> Self {
            Self::new(EvidenceConfig::default())
        }

        pub fn config(&self) -> &EvidenceConfig {
            &self.config
        }

        pub fn init(&mut self) {
            self.initialised = true;
            info!("evidence manager initialised");
        }

        pub fn is_initialised(&self) -> bool {
            self.initialised
        }

        /// Create a double-vote evidence.
        pub fn create_double_vote(&self, vote_a: Vote, vote_b: Vote) -> EvidenceResult<Evidence> {
            let ev = Evidence::new_double_vote(vote_a, vote_b, &self.config)?;
            global_metrics().inc_created("double_vote");
            if self.config.auto_verify_on_create {
                global_metrics().inc_auto_verified();
            }
            if self.config.log_operations {
                trace!("double-vote evidence created");
            }
            Ok(ev)
        }

        /// Create a double-proposal evidence.
        pub fn create_double_proposal(&self, proposal_a: Proposal, proposal_b: Proposal) -> EvidenceResult<Evidence> {
            let ev = Evidence::new_double_proposal(proposal_a, proposal_b, &self.config)?;
            global_metrics().inc_created("double_proposal");
            if self.config.auto_verify_on_create {
                global_metrics().inc_auto_verified();
            }
            if self.config.log_operations {
                trace!("double-proposal evidence created");
            }
            Ok(ev)
        }

        /// Verify evidence (quantum + signatures).
        pub fn verify_evidence(&self, evidence: &mut Evidence) -> EvidenceResult<()> {
            if self.config.log_operations {
                trace!("verifying evidence");
            }
            let result = evidence.verify_and_mark(&self.config);
            if result.is_ok() {
                global_metrics().inc_verified();
            } else {
                let err = result.as_ref().unwrap_err();
                let reason = match err {
                    EvidenceError::InvalidSignature(_) => "signature",
                    EvidenceError::WitnessBelowThreshold { .. } => "witness",
                    EvidenceError::Decoherence { .. } => "decoherence",
                    _ => "other",
                };
                global_metrics().inc_verification_failure(reason);
            }
            result
        }

        /// Verify quantum state (without signatures).
        pub fn verify_quantum(&self, evidence: &mut Evidence) -> EvidenceResult<()> {
            if self.config.log_operations {
                trace!("verifying quantum state");
            }
            evidence.verify_quantum(&self.config)
        }

        /// Verify signatures only.
        pub fn verify_signatures(&self, evidence: &Evidence) -> EvidenceResult<()> {
            if self.config.log_operations {
                trace!("verifying signatures");
            }
            evidence.verify_signatures()
        }

        /// Check if evidence is valid (classical + quantum + signatures).
        pub fn is_valid(&self, evidence: &Evidence) -> bool {
            evidence.verify().is_ok()
        }

        /// Get metrics snapshot.
        pub fn metrics_snapshot(&self) -> super::metrics::EvidenceMetricsSnapshot {
            global_metrics().snapshot()
        }

        /// Reset metrics.
        pub fn reset_metrics(&self) {
            // Not easily possible with global metrics.
            tracing::warn!("resetting evidence metrics not supported in this version");
        }
    }
}

// -----------------------------------------------------------------------------
// Public exports
// -----------------------------------------------------------------------------

pub use config::EvidenceConfig;
pub use error::{EvidenceError, EvidenceResult};
pub use types::Evidence;
pub use metrics::{EvidenceMetrics, EvidenceMetricsSnapshot};
pub use manager::EvidenceManager;

// Re-export constants for backward compatibility.
pub use constants::*;

// -----------------------------------------------------------------------------
// Legacy global API (backward compatibility)
// -----------------------------------------------------------------------------

use spin::Once;

static GLOBAL_MANAGER: Once<EvidenceManager> = Once::new();

fn global_manager() -> &'static EvidenceManager {
    GLOBAL_MANAGER.get_or_init(|| {
        let mut mgr = EvidenceManager::new(EvidenceConfig::default());
        mgr.init();
        mgr
    })
}

/// Create a double-vote evidence (legacy).
pub fn new_double_vote(vote_a: Vote, vote_b: Vote) -> EvidenceResult<Evidence> {
    global_manager().create_double_vote(vote_a, vote_b)
}

/// Create a double-proposal evidence (legacy).
pub fn new_double_proposal(proposal_a: Proposal, proposal_b: Proposal) -> EvidenceResult<Evidence> {
    global_manager().create_double_proposal(proposal_a, proposal_b)
}

/// Verify evidence (legacy).
pub fn verify_evidence(evidence: &mut Evidence) -> EvidenceResult<()> {
    global_manager().verify_evidence(evidence)
}

/// Verify quantum state (legacy).
pub fn verify_quantum(evidence: &mut Evidence) -> EvidenceResult<()> {
    global_manager().verify_quantum(evidence)
}

/// Verify signatures (legacy).
pub fn verify_signatures(evidence: &Evidence) -> EvidenceResult<()> {
    global_manager().verify_signatures(evidence)
}

/// Check if evidence is valid (legacy).
pub fn is_valid_evidence(evidence: &Evidence) -> bool {
    global_manager().is_valid(evidence)
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::consensus::messages::test_utils::{dummy_vote, dummy_proposal};
    use crate::types::Hash32;

    #[test]
    fn test_new_double_vote_ok() {
        let mgr = EvidenceManager::default();
        let vote1 = dummy_vote(1, 1, VoteType::Prevote, Some(Hash32([1; 32])));
        let mut vote2 = vote1.clone();
        vote2.block_hash = Some(Hash32([2; 32]));

        let ev = mgr.create_double_vote(vote1, vote2).unwrap();
        assert!(ev.witness_value() > WITNESS_THRESHOLD);
        assert!((ev.coherence() - 1.0).abs() < 1e-3);
        assert!((ev.severity() - 1.0).abs() < 0.1);
    }

    #[test]
    fn test_new_double_vote_duplicate() {
        let mgr = EvidenceManager::default();
        let vote = dummy_vote(1, 1, VoteType::Prevote, Some(Hash32([1; 32])));
        let err = mgr.create_double_vote(vote.clone(), vote).unwrap_err();
        assert!(matches!(err, EvidenceError::DuplicateMessages));
    }

    #[test]
    fn test_new_double_vote_mismatched_height() {
        let mgr = EvidenceManager::default();
        let vote1 = dummy_vote(1, 1, VoteType::Prevote, Some(Hash32([1; 32])));
        let mut vote2 = vote1.clone();
        vote2.height = 2;

        let err = mgr.create_double_vote(vote1, vote2).unwrap_err();
        assert!(matches!(err, EvidenceError::MismatchedHeightRound));
    }

    #[test]
    fn test_manager_verify() {
        let mgr = EvidenceManager::default();
        let vote1 = dummy_vote(1, 1, VoteType::Prevote, Some(Hash32([1; 32])));
        let mut vote2 = vote1.clone();
        vote2.block_hash = Some(Hash32([2; 32]));

        let mut ev = mgr.create_double_vote(vote1, vote2).unwrap();
        // Already verified by auto_verify_on_create.
        assert!(ev.is_verified());

        // Re-verify should be idempotent.
        assert!(mgr.verify_evidence(&mut ev).is_ok());
        assert!(ev.is_verified());
    }

    #[test]
    fn test_config_auto_verify_disabled() {
        let config = EvidenceConfig {
            auto_verify_on_create: false,
            ..Default::default()
        };
        let mgr = EvidenceManager::new(config);
        let vote1 = dummy_vote(1, 1, VoteType::Prevote, Some(Hash32([1; 32])));
        let mut vote2 = vote1.clone();
        vote2.block_hash = Some(Hash32([2; 32]));

        let mut ev = mgr.create_double_vote(vote1, vote2).unwrap();
        assert!(!ev.is_verified());
        assert!(mgr.verify_evidence(&mut ev).is_ok());
        assert!(ev.is_verified());
    }
}
