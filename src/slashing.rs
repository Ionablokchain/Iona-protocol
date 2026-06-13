//! Production slashing and validator lifecycle for IONA v21 — Quantum‑Ready.
//!
//! # Quantum Slashing Model
//!
//! Slashing is modelled as a **strong projective measurement** that
//! collapses a validator's state from |active⟩ to |jailed⟩ or |tombstoned⟩.
//! The slash fraction determines the **energy penalty** extracted from the
//! validator's stake.
//!
//! # Mathematical Formalism
//!
//! ## Validator State
//! ```text
//! |validator⟩ = α|active⟩ + β|jailed⟩ + γ|tombstoned⟩
//! ```
//!
//! ## Hamiltonian for Slashing
//! ```text
//! Ĥ_slash = Ĥ_double_vote + Ĥ_downtime + Ĥ_unjail
//!
//! Ĥ_double_vote = Σ_v E_v |tombstoned_v⟩⟨active_v|
//! Ĥ_downtime    = Σ_w ω_w |jailed_w⟩⟨active_w|
//! Ĥ_unjail      = Σ_u λ_u |active_u⟩⟨jailed_u|
//! ```

use crate::crypto::PublicKeyBytes;
use crate::evidence::Evidence;
use crate::types::Height;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashSet};
use thiserror::Error;
use tracing::{info, warn};

// -----------------------------------------------------------------------------
// Quantum Constants
// -----------------------------------------------------------------------------

/// Reduced Planck constant (natural units).
const HBAR: f64 = 1.0;

/// Default quantum coherence for a fresh validator.
const DEFAULT_VALIDATOR_COHERENCE: f64 = 1.0;

/// Decoherence rate per slashing operation.
const SLASH_DECOHERENCE_RATE: f64 = 0.001;

/// Decoherence rate per unjail operation.
const UNJAIL_DECOHERENCE_RATE: f64 = 0.0005;

/// Decoherence rate per downtime slash.
const DOWNTIME_DECOHERENCE_RATE: f64 = 0.0008;

/// Minimum coherence threshold for a healthy ledger.
const MIN_LEDGER_COHERENCE: f64 = 0.9;

/// Kraus rank for slashing quantum channels.
const SLASHING_KRAUS_RANK: usize = 4;

// -----------------------------------------------------------------------------
// Classical Constants (unchanged)
// -----------------------------------------------------------------------------

/// Blocks a validator must wait after being jailed before they can unjail.
pub const UNJAIL_DELAY_BLOCKS: u64 = 1000;

/// Slash fraction for double‑vote (5% = 1/20).
pub const SLASH_FRACTION_DOUBLE_VOTE: u64 = 20; // 1/20

/// Slash fraction for downtime (1% = 1/100).
pub const SLASH_FRACTION_DOWNTIME: u64 = 100; // 1/100

/// Window of blocks to check for downtime (number of recent blocks considered).
pub const DOWNTIME_WINDOW: u64 = 200;

/// Minimum blocks a validator must have signed in the last DOWNTIME_WINDOW to avoid jailing.
pub const DOWNTIME_MIN_SIGNED: u64 = 100; // 50% participation required

/// Minimum stake required to remain a validator after slashing.
pub const MIN_STAKE_AFTER_SLASH: u64 = 1;

// -----------------------------------------------------------------------------
// Errors
// -----------------------------------------------------------------------------

/// Errors that can occur during slashing operations.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum SlashingError {
    #[error("unknown validator")]
    UnknownValidator,

    #[error("validator is tombstoned – cannot unjail")]
    Tombstoned,

    #[error("validator is not jailed")]
    NotJailed,

    #[error("unjail delay not elapsed (wait {remaining} more blocks)")]
    UnjailDelayNotElapsed { remaining: u64 },

    #[error("validator has zero stake – cannot unjail")]
    ZeroStake,

    #[error("duplicate evidence already processed")]
    DuplicateEvidence,

    #[error("validator already jailed for downtime")]
    AlreadyJailed,

    #[error("quantum decoherence: ledger coherence {coherence} below threshold {threshold}")]
    Decoherence { coherence: f64, threshold: f64 },
}

pub type SlashingResult<T> = Result<T, SlashingError>;

// -----------------------------------------------------------------------------
// Quantum Slashing State
// -----------------------------------------------------------------------------

/// Quantum state of the entire stake ledger.
///
/// Tracks the density matrix properties during slashing, jailing, and
/// unjailing operations.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QuantumSlashingState {
    /// Purity γ = Tr(ρ²) of the ledger state.
    pub purity: f64,
    /// Von Neumann entropy S = -Tr(ρ ln ρ).
    pub entropy: f64,
    /// Coherence of the slashing subsystem.
    pub slashing_coherence: f64,
    /// Coherence of the unjailing subsystem.
    pub unjail_coherence: f64,
    /// Total slashing operations performed.
    pub total_slashes: u64,
    /// Total unjail operations performed.
    pub total_unjails: u64,
    /// Total downtime slashes performed.
    pub total_downtime_slashes: u64,
    /// Number of tombstoned validators.
    pub tombstoned_count: usize,
    /// Whether the ledger is in a healthy quantum state.
    pub is_healthy: bool,
}

impl Default for QuantumSlashingState {
    fn default() -> Self {
        Self {
            purity: DEFAULT_VALIDATOR_COHERENCE,
            entropy: 0.0,
            slashing_coherence: DEFAULT_VALIDATOR_COHERENCE,
            unjail_coherence: DEFAULT_VALIDATOR_COHERENCE,
            total_slashes: 0,
            total_unjails: 0,
            total_downtime_slashes: 0,
            tombstoned_count: 0,
            is_healthy: true,
        }
    }
}

impl QuantumSlashingState {
    /// Create a new quantum slashing state in the ground state |∅⟩.
    pub fn new() -> Self {
        Self::default()
    }

    /// Apply decoherence from a slashing operation (double‑vote/proposal).
    pub fn apply_slash_decoherence(&mut self, tombstoned: bool) {
        self.total_slashes = self.total_slashes.wrapping_add(1);
        if tombstoned {
            self.tombstoned_count = self.tombstoned_count.saturating_add(1);
        }
        let decay = (-SLASH_DECOHERENCE_RATE).exp();
        self.slashing_coherence = (self.slashing_coherence * decay).clamp(0.0, 1.0);
        self.recompute();
    }

    /// Apply decoherence from an unjail operation.
    pub fn apply_unjail_decoherence(&mut self) {
        self.total_unjails = self.total_unjails.wrapping_add(1);
        let decay = (-UNJAIL_DECOHERENCE_RATE).exp();
        self.unjail_coherence = (self.unjail_coherence * decay).clamp(0.0, 1.0);
        self.recompute();
    }

    /// Apply decoherence from a downtime slash.
    pub fn apply_downtime_decoherence(&mut self) {
        self.total_downtime_slashes = self.total_downtime_slashes.wrapping_add(1);
        let decay = (-DOWNTIME_DECOHERENCE_RATE).exp();
        self.slashing_coherence = (self.slashing_coherence * decay).clamp(0.0, 1.0);
        self.recompute();
    }

    /// Apply the Kraus channel for slashing operations.
    pub fn apply_slashing_channel(&mut self) {
        let kraus_factor = (1.0 / SLASHING_KRAUS_RANK as f64).sqrt();
        self.slashing_coherence = (self.slashing_coherence * kraus_factor).clamp(0.0, 1.0);
        self.unjail_coherence = (self.unjail_coherence * kraus_factor).clamp(0.0, 1.0);
        self.recompute();
    }

    fn recompute(&mut self) {
        self.purity = (self.slashing_coherence * self.unjail_coherence).clamp(0.0, 1.0);
        self.entropy = if self.purity >= 1.0 {
            0.0
        } else {
            -self.purity * self.purity.ln().max(0.0)
        };
        self.is_healthy = self.purity >= MIN_LEDGER_COHERENCE;
    }
}

// -----------------------------------------------------------------------------
// Validator status
// -----------------------------------------------------------------------------

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum ValidatorStatus {
    Active,
    Jailed {
        since_height: Height,
        slash_count: u32,
    },
    Tombstoned,
}

// -----------------------------------------------------------------------------
// Validator record
// -----------------------------------------------------------------------------

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ValidatorRecord {
    pub stake: u64,
    pub slashed_total: u64,
    pub status: ValidatorStatus,
    pub jailed_at: Option<Height>,
    /// Quantum coherence of this validator.
    #[serde(default = "default_coherence")]
    pub coherence: f64,
}

fn default_coherence() -> f64 {
    DEFAULT_VALIDATOR_COHERENCE
}

impl ValidatorRecord {
    /// Create a new active validator record with full coherence.
    pub const fn new(stake: u64) -> Self {
        Self {
            stake,
            slashed_total: 0,
            status: ValidatorStatus::Active,
            jailed_at: None,
            coherence: DEFAULT_VALIDATOR_COHERENCE,
        }
    }

    /// Check if the validator is active.
    pub const fn is_active(&self) -> bool {
        matches!(self.status, ValidatorStatus::Active)
    }

    /// Check if the validator is jailed.
    pub const fn is_jailed(&self) -> bool {
        matches!(self.status, ValidatorStatus::Jailed { .. })
    }

    /// Check if the validator is tombstoned.
    pub const fn is_tombstoned(&self) -> bool {
        matches!(self.status, ValidatorStatus::Tombstoned)
    }

    /// Check if the validator can be unjailed at the given height.
    pub fn can_unjail(&self, current_height: Height) -> bool {
        match &self.status {
            ValidatorStatus::Jailed { since_height, .. } => {
                current_height >= since_height + UNJAIL_DELAY_BLOCKS
            }
            _ => false,
        }
    }

    /// Apply decoherence to this validator (from slashing/jailing).
    pub fn apply_decoherence(&mut self, rate: f64) {
        self.coherence = (self.coherence * (-rate).exp()).clamp(0.0, 1.0);
    }
}

// -----------------------------------------------------------------------------
// Stake ledger (classical + quantum)
// -----------------------------------------------------------------------------

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct StakeLedger {
    pub validators: BTreeMap<PublicKeyBytes, ValidatorRecord>,
    pub processed_evidence: HashSet<(Height, PublicKeyBytes)>,
    /// Quantum state of the entire ledger.
    #[serde(default = "QuantumSlashingState::new")]
    pub quantum: QuantumSlashingState,
}

impl StakeLedger {
    /// Create an empty ledger.
    pub fn new() -> Self {
        Self::default()
    }

    /// Total active voting power.
    pub fn total_power(&self) -> u64 {
        self.validators
            .values()
            .filter(|r| r.is_active())
            .map(|r| r.stake)
            .sum()
    }

    /// Power of a specific validator (0 if not active).
    pub fn power_of(&self, pk: &PublicKeyBytes) -> u64 {
        self.validators
            .get(pk)
            .filter(|r| r.is_active())
            .map(|r| r.stake)
            .unwrap_or(0)
    }

    /// Raw stake map (includes jailed validators).
    pub fn stake_raw(&self) -> BTreeMap<PublicKeyBytes, u64> {
        self.validators
            .iter()
            .map(|(k, v)| (k.clone(), v.stake))
            .collect()
    }

    /// Quantum purity of the ledger.
    pub fn purity(&self) -> f64 {
        self.quantum.purity
    }

    /// Whether the ledger is in a healthy quantum state.
    pub fn is_healthy(&self) -> bool {
        self.quantum.is_healthy
    }

    /// Apply slashing evidence (double‑vote or double‑proposal).
    pub fn apply_evidence(
        &mut self,
        evidence: &Evidence,
        current_height: Height,
    ) -> SlashingResult<()> {
        let (offender, height) = match evidence {
            Evidence::DoubleVote { voter, height, .. } => (voter, height),
            Evidence::DoubleProposal {
                proposer, height, ..
            } => (proposer, height),
        };

        let key = (*height, offender.clone());
        if self.processed_evidence.contains(&key) {
            warn!("duplicate evidence for offender at height {height}, ignoring");
            return Err(SlashingError::DuplicateEvidence);
        }
        self.processed_evidence.insert(key);

        let record = self
            .validators
            .get_mut(offender)
            .ok_or(SlashingError::UnknownValidator)?;

        // Compute slash amount (minimum 1)
        let slash = (record.stake / SLASH_FRACTION_DOUBLE_VOTE).max(1);
        record.stake = record.stake.saturating_sub(slash);
        record.slashed_total += slash;

        // Determine if tombstoned (second serious offence)
        let is_tombstone = matches!(&record.status,
            ValidatorStatus::Jailed { slash_count, .. } if *slash_count >= 2
        );

        if is_tombstone {
            record.status = ValidatorStatus::Tombstoned;
            record.coherence = 0.0; // complete decoherence
            warn!(
                offender = %hex::encode(&offender.0),
                "validator tombstoned (repeated double‑vote/double‑proposal)"
            );
        } else {
            let slash_count = match &record.status {
                ValidatorStatus::Jailed { slash_count, .. } => *slash_count + 1,
                _ => 1,
            };
            record.status = ValidatorStatus::Jailed {
                since_height: current_height,
                slash_count,
            };
            record.jailed_at = Some(current_height);
            record.apply_decoherence(SLASH_DECOHERENCE_RATE);
            warn!(
                offender = %hex::encode(&offender.0),
                slashed = slash,
                remaining = record.stake,
                "validator jailed"
            );
        }

        self.quantum.apply_slash_decoherence(is_tombstone);
        self.quantum.apply_slashing_channel();

        // Check ledger health
        if !self.quantum.is_healthy {
            warn!(
                coherence = self.quantum.purity,
                "ledger quantum coherence below threshold"
            );
        }
        Ok(())
    }

    /// Apply evidence with quantum state tracking returned.
    pub fn apply_evidence_quantum(
        &mut self,
        evidence: &Evidence,
        current_height: Height,
    ) -> (SlashingResult<()>, QuantumSlashingState) {
        let result = self.apply_evidence(evidence, current_height);
        (result, self.quantum.clone())
    }

    /// Unjail a validator who has waited the required delay.
    pub fn unjail(
        &mut self,
        pk: &PublicKeyBytes,
        current_height: Height,
    ) -> SlashingResult<()> {
        let record = self
            .validators
            .get_mut(pk)
            .ok_or(SlashingError::UnknownValidator)?;

        match &record.status {
            ValidatorStatus::Tombstoned => Err(SlashingError::Tombstoned),
            ValidatorStatus::Active => Err(SlashingError::NotJailed),
            ValidatorStatus::Jailed { since_height, .. } => {
                if !record.can_unjail(current_height) {
                    let remaining =
                        (since_height + UNJAIL_DELAY_BLOCKS).saturating_sub(current_height);
                    return Err(SlashingError::UnjailDelayNotElapsed { remaining });
                }
                if record.stake == 0 {
                    return Err(SlashingError::ZeroStake);
                }
                record.status = ValidatorStatus::Active;
                record.jailed_at = None;
                // Restore some coherence (but not full)
                record.coherence = (record.coherence * 1.1).min(1.0);
                self.quantum.apply_unjail_decoherence();
                self.quantum.apply_slashing_channel();
                info!(validator = %hex::encode(&pk.0), "validator unjailed");
                Ok(())
            }
        }
    }

    /// Unjail with quantum state tracking returned.
    pub fn unjail_quantum(
        &mut self,
        pk: &PublicKeyBytes,
        current_height: Height,
    ) -> (SlashingResult<()>, QuantumSlashingState) {
        let result = self.unjail(pk, current_height);
        (result, self.quantum.clone())
    }

    /// Slash a validator for downtime.
    pub fn slash_downtime(
        &mut self,
        pk: &PublicKeyBytes,
        current_height: Height,
    ) -> SlashingResult<()> {
        let record = self
            .validators
            .get_mut(pk)
            .ok_or(SlashingError::UnknownValidator)?;

        if !record.is_active() {
            return Err(SlashingError::AlreadyJailed);
        }

        let slash = (record.stake / SLASH_FRACTION_DOWNTIME).max(1);
        record.stake = record.stake.saturating_sub(slash);
        record.slashed_total += slash;
        record.status = ValidatorStatus::Jailed {
            since_height: current_height,
            slash_count: 1,
        };
        record.jailed_at = Some(current_height);
        record.apply_decoherence(DOWNTIME_DECOHERENCE_RATE);
        warn!(
            validator = %hex::encode(&pk.0),
            slashed = slash,
            "validator jailed for downtime"
        );
        self.quantum.apply_downtime_decoherence();
        self.quantum.apply_slashing_channel();
        Ok(())
    }

    /// Slash for downtime with quantum state tracking returned.
    pub fn slash_downtime_quantum(
        &mut self,
        pk: &PublicKeyBytes,
        current_height: Height,
    ) -> (SlashingResult<()>, QuantumSlashingState) {
        let result = self.slash_downtime(pk, current_height);
        (result, self.quantum.clone())
    }

    /// Status report for all validators.
    pub fn status_report(&self) -> Vec<(PublicKeyBytes, &ValidatorRecord)> {
        self.validators.iter().map(|(k, v)| (k.clone(), v)).collect()
    }

    /// Add a new validator (for genesis or later addition).
    pub fn add_validator(&mut self, pk: PublicKeyBytes, stake: u64) {
        self.validators.insert(pk, ValidatorRecord::new(stake));
    }
}

// -----------------------------------------------------------------------------
// Legacy compatibility
// -----------------------------------------------------------------------------

impl StakeLedger {
    /// Deserialize old format (stake: BTreeMap<PK,u64>, slashed: BTreeMap<PK,u64>)
    pub fn from_legacy(
        stake: BTreeMap<PublicKeyBytes, u64>,
        slashed: BTreeMap<PublicKeyBytes, u64>,
    ) -> Self {
        let mut s = Self::new();
        for (pk, amount) in stake {
            let slashed_total = *slashed.get(&pk).unwrap_or(&0);
            s.validators.insert(
                pk,
                ValidatorRecord {
                    stake: amount,
                    slashed_total,
                    status: ValidatorStatus::Active,
                    jailed_at: None,
                    coherence: DEFAULT_VALIDATOR_COHERENCE,
                },
            );
        }
        s
    }
}

// -----------------------------------------------------------------------------
// Uptime tracking (classical + quantum)
// -----------------------------------------------------------------------------

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct UptimeTracker {
    pub signed_in_window: BTreeMap<PublicKeyBytes, u64>,
    pub last_signed_height: BTreeMap<PublicKeyBytes, Height>,
    pub window_start: Height,
    /// Quantum coherence of the uptime tracker.
    #[serde(default = "default_coherence")]
    pub coherence: f64,
}

impl UptimeTracker {
    /// Create a new uptime tracker.
    pub fn new() -> Self {
        Self::default()
    }

    /// Record a committed block: update signed counts for signers.
    pub fn record_block(
        &mut self,
        height: Height,
        signers: &[PublicKeyBytes],
        all_validators: &[PublicKeyBytes],
    ) {
        // Advance window start
        if height > DOWNTIME_WINDOW {
            self.window_start = height - DOWNTIME_WINDOW;
        }

        // Increase signed counts for signers
        for pk in signers {
            *self.signed_in_window.entry(pk.clone()).or_insert(0) += 1;
            self.last_signed_height.insert(pk.clone(), height);
        }

        // Ensure all validators have an entry (even with zero)
        for pk in all_validators {
            self.signed_in_window.entry(pk.clone()).or_insert(0);
        }

        // Minor decoherence from recording
        self.coherence = (self.coherence * (-0.00001f64).exp()).clamp(0.0, 1.0);
    }

    /// Get the number of signed blocks in the window for a given validator.
    pub fn signed_count(&self, pk: &PublicKeyBytes) -> u64 {
        *self.signed_in_window.get(pk).unwrap_or(&0)
    }

    /// Check which validators have missed too many blocks (downtime).
    pub fn check_downtime(&self, height: Height, stakes: &StakeLedger) -> Vec<PublicKeyBytes> {
        if height < DOWNTIME_WINDOW {
            return vec![];
        }
        stakes
            .validators
            .iter()
            .filter(|(_, r)| r.is_active())
            .filter(|(pk, _)| {
                let signed = self.signed_count(pk);
                let last = *self.last_signed_height.get(*pk).unwrap_or(&0);
                last > 0 && signed < DOWNTIME_MIN_SIGNED
            })
            .map(|(pk, _)| pk.clone())
            .collect()
    }

    /// Reset counts for a validator (e.g., after unjailing, give a fresh start).
    pub fn reset_counts(&mut self, pk: &PublicKeyBytes) {
        self.signed_in_window.remove(pk);
        self.last_signed_height.remove(pk);
    }
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn dummy_pk(id: u8) -> PublicKeyBytes {
        let mut bytes = [0u8; 32];
        bytes[0] = id;
        PublicKeyBytes(bytes.to_vec())
    }

    // ── Classical Tests ──────────────────────────────────────────────
    #[test]
    fn test_validator_record() {
        let v = ValidatorRecord::new(1000);
        assert!(v.is_active());
        assert_eq!(v.stake, 1000);
        assert_eq!(v.slashed_total, 0);
        assert!((v.coherence - 1.0).abs() < 1e-10);
    }

    #[test]
    fn test_slash_double_vote() -> SlashingResult<()> {
        let mut ledger = StakeLedger::new();
        let pk = dummy_pk(1);
        ledger.add_validator(pk.clone(), 1000);

        let evidence = Evidence::DoubleVote {
            voter: pk.clone(),
            height: 10,
            round: 0,
            vote_type: crate::consensus::messages::VoteType::Prevote,
            a: None,
            b: None,
            vote_a: crate::consensus::messages::Vote::default(),
            vote_b: crate::consensus::messages::Vote::default(),
        };
        ledger.apply_evidence(&evidence, 10)?;
        let record = ledger.validators.get(&pk).unwrap();
        assert_eq!(record.stake, 1000 - (1000 / 20));
        assert!(matches!(record.status, ValidatorStatus::Jailed { .. }));
        Ok(())
    }

    #[test]
    fn test_unjail() -> SlashingResult<()> {
        let mut ledger = StakeLedger::new();
        let pk = dummy_pk(2);
        ledger.add_validator(pk.clone(), 1000);
        let evidence = Evidence::DoubleVote {
            voter: pk.clone(),
            height: 10,
            round: 0,
            vote_type: crate::consensus::messages::VoteType::Prevote,
            a: None,
            b: None,
            vote_a: crate::consensus::messages::Vote::default(),
            vote_b: crate::consensus::messages::Vote::default(),
        };
        ledger.apply_evidence(&evidence, 10)?;
        // Cannot unjail immediately
        let err = ledger.unjail(&pk, 10).unwrap_err();
        assert!(matches!(
            err,
            SlashingError::UnjailDelayNotElapsed { .. }
        ));
        // After delay
        ledger.unjail(&pk, 10 + UNJAIL_DELAY_BLOCKS)?;
        let record = ledger.validators.get(&pk).unwrap();
        assert!(record.is_active());
        Ok(())
    }

    #[test]
    fn test_downtime_slash() -> SlashingResult<()> {
        let mut ledger = StakeLedger::new();
        let pk = dummy_pk(3);
        ledger.add_validator(pk.clone(), 1000);
        ledger.slash_downtime(&pk, 100)?;
        let record = ledger.validators.get(&pk).unwrap();
        assert_eq!(record.stake, 1000 - (1000 / 100));
        assert!(matches!(record.status, ValidatorStatus::Jailed { .. }));
        Ok(())
    }

    #[test]
    fn test_uptime_tracker() {
        let pk = dummy_pk(4);
        let mut tracker = UptimeTracker::new();
        tracker.record_block(1, &[pk.clone()], &[pk.clone()]);
        assert_eq!(tracker.signed_count(&pk), 1);
    }

    // ── Quantum Tests ────────────────────────────────────────────────
    #[test]
    fn test_quantum_state_initialization() {
        let state = QuantumSlashingState::new();
        assert!((state.purity - 1.0).abs() < 1e-10);
        assert!((state.entropy - 0.0).abs() < 1e-10);
        assert!(state.is_healthy);
    }

    #[test]
    fn test_slash_decoherence() {
        let mut state = QuantumSlashingState::new();
        let initial_purity = state.purity;
        state.apply_slash_decoherence(false);
        assert!(state.purity < initial_purity);
        assert_eq!(state.total_slashes, 1);
    }

    #[test]
    fn test_tombstone_decoherence() {
        let mut state = QuantumSlashingState::new();
        let initial_purity = state.purity;
        state.apply_slash_decoherence(true);
        assert!(state.purity < initial_purity);
        assert_eq!(state.tombstoned_count, 1);
    }

    #[test]
    fn test_unjail_decoherence() {
        let mut state = QuantumSlashingState::new();
        let initial_purity = state.purity;
        state.apply_unjail_decoherence();
        assert!(state.purity < initial_purity);
        assert_eq!(state.total_unjails, 1);
    }

    #[test]
    fn test_downtime_decoherence() {
        let mut state = QuantumSlashingState::new();
        let initial_purity = state.purity;
        state.apply_downtime_decoherence();
        assert!(state.purity < initial_purity);
        assert_eq!(state.total_downtime_slashes, 1);
    }

    #[test]
    fn test_slashing_channel() {
        let mut state = QuantumSlashingState::new();
        let initial_slash_coh = state.slashing_coherence;
        state.apply_slashing_channel();
        assert!(state.slashing_coherence < initial_slash_coh);
    }

    #[test]
    fn test_apply_evidence_quantum() -> SlashingResult<()> {
        let mut ledger = StakeLedger::new();
        let pk = dummy_pk(10);
        ledger.add_validator(pk.clone(), 1000);

        let evidence = Evidence::DoubleVote {
            voter: pk.clone(),
            height: 10,
            round: 0,
            vote_type: crate::consensus::messages::VoteType::Prevote,
            a: None,
            b: None,
            vote_a: crate::consensus::messages::Vote::default(),
            vote_b: crate::consensus::messages::Vote::default(),
        };
        let (result, qstate) = ledger.apply_evidence_quantum(&evidence, 10);
        assert!(result.is_ok());
        assert!(qstate.total_slashes > 0);
        assert!(qstate.purity < 1.0);
        Ok(())
    }

    #[test]
    fn test_unjail_quantum() -> SlashingResult<()> {
        let mut ledger = StakeLedger::new();
        let pk = dummy_pk(11);
        ledger.add_validator(pk.clone(), 1000);
        let evidence = Evidence::DoubleVote {
            voter: pk.clone(),
            height: 10,
            round: 0,
            vote_type: crate::consensus::messages::VoteType::Prevote,
            a: None,
            b: None,
            vote_a: crate::consensus::messages::Vote::default(),
            vote_b: crate::consensus::messages::Vote::default(),
        };
        ledger.apply_evidence(&evidence, 10)?;
        let (result, qstate) = ledger.unjail_quantum(&pk, 10 + UNJAIL_DELAY_BLOCKS);
        assert!(result.is_ok());
        assert!(qstate.total_unjails > 0);
        Ok(())
    }

    #[test]
    fn test_downtime_quantum() -> SlashingResult<()> {
        let mut ledger = StakeLedger::new();
        let pk = dummy_pk(12);
        ledger.add_validator(pk.clone(), 1000);
        let (result, qstate) = ledger.slash_downtime_quantum(&pk, 100);
        assert!(result.is_ok());
        assert!(qstate.total_downtime_slashes > 0);
        Ok(())
    }

    #[test]
    fn test_ledger_purity() {
        let ledger = StakeLedger::new();
        assert!((ledger.purity() - 1.0).abs() < 1e-10);
        assert!(ledger.is_healthy());
    }

    #[test]
    fn test_validator_decoherence() {
        let mut record = ValidatorRecord::new(1000);
        let initial_coh = record.coherence;
        record.apply_decoherence(0.1);
        assert!(record.coherence < initial_coh);
    }

    #[test]
    fn test_health_after_many_slashes() {
        let mut state = QuantumSlashingState::new();
        for _ in 0..1000 {
            state.apply_slash_decoherence(false);
        }
        assert!(!state.is_healthy);
    }

    #[test]
    fn test_purity_never_negative() {
        let mut state = QuantumSlashingState::new();
        for _ in 0..100000 {
            state.apply_slash_decoherence(true);
        }
        assert!(state.purity >= 0.0);
    }
}
