//! Quorum calculator with diagnostic output for IONA v28.
//!
//! When consensus stalls, this module tells you exactly WHY:
//!   - missing_quorum: have=2 need=3
//!   - validators_online: [A,B] missing=[C]
//!   - p2p_connected_validators=2/3
//!
//! It provides detailed diagnostics for quorum analysis and validator
//! connectivity, helping operators quickly identify the cause of stalls.

use crate::consensus::validator_set::{Validator, ValidatorSet, VotingPower};
use crate::crypto::PublicKeyBytes;
use crate::types::Hash32;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::fmt;

// -----------------------------------------------------------------------------
// QuorumDiagnostic
// -----------------------------------------------------------------------------

/// Diagnostic information about quorum status.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QuorumDiagnostic {
    /// Total validators in the set.
    pub total_validators: usize,
    /// Total voting power.
    pub total_power: VotingPower,
    /// Required power for quorum (2f+1).
    pub quorum_threshold: VotingPower,
    /// Current accumulated power.
    pub current_power: VotingPower,
    /// Whether quorum is reached.
    pub has_quorum: bool,
    /// Validators that have voted (hex-encoded first 8 bytes of pk).
    pub voted: Vec<String>,
    /// Validators that have NOT voted (hex-encoded first 8 bytes of pk).
    pub missing: Vec<String>,
    /// Human-readable reason if quorum is not met.
    pub reason: Option<String>,
}

impl fmt::Display for QuorumDiagnostic {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.has_quorum {
            write!(
                f,
                "quorum_ok: {}/{} power ({}/{} validators)",
                self.current_power,
                self.quorum_threshold,
                self.voted.len(),
                self.total_validators
            )
        } else {
            write!(
                f,
                "NO_QUORUM: have={}/{} power, voted=[{}], missing=[{}]",
                self.current_power,
                self.quorum_threshold,
                self.voted.join(","),
                self.missing.join(",")
            )
        }
    }
}

// -----------------------------------------------------------------------------
// QuorumCalculator
// -----------------------------------------------------------------------------

/// Enhanced quorum calculator that provides diagnostics.
#[derive(Debug, Clone)]
pub struct QuorumCalculator {
    vset: ValidatorSet,
    threshold: VotingPower,
}

impl QuorumCalculator {
    /// Create a new quorum calculator for the given validator set.
    #[must_use]
    pub fn new(vset: &ValidatorSet) -> Self {
        let total = vset.total_power();
        let threshold = (total * 2 / 3) + 1;
        Self {
            vset: vset.clone(),
            threshold,
        }
    }

    /// Get the quorum threshold.
    #[must_use]
    pub fn threshold(&self) -> VotingPower {
        self.threshold
    }

    /// Total voting power in the validator set.
    #[must_use]
    pub fn total_power(&self) -> VotingPower {
        self.vset.total_power()
    }

    /// Number of validators.
    #[must_use]
    pub fn validator_count(&self) -> usize {
        self.vset.vals.len()
    }

    /// Check if a set of voters reaches quorum.
    ///
    /// Returns a diagnostic that includes all relevant details.
    #[must_use]
    pub fn check(&self, voters: &[PublicKeyBytes]) -> QuorumDiagnostic {
        let voter_set: HashSet<&PublicKeyBytes> = voters.iter().collect();
        let mut current_power: VotingPower = 0;
        let mut voted = Vec::new();
        let mut missing = Vec::new();

        for val in &self.vset.vals {
            let pk_hex = hex::encode(&val.pk.0[..8]);
            if voter_set.contains(&val.pk) {
                current_power += val.power;
                voted.push(pk_hex);
            } else {
                missing.push(pk_hex);
            }
        }

        let has_quorum = current_power >= self.threshold;
        let reason = if has_quorum {
            None
        } else {
            Some(format!(
                "missing_quorum: have={} need={} (voted={}/{} validators)",
                current_power,
                self.threshold,
                voted.len(),
                self.vset.vals.len(),
            ))
        };

        QuorumDiagnostic {
            total_validators: self.vset.vals.len(),
            total_power: self.vset.total_power(),
            quorum_threshold: self.threshold,
            current_power,
            has_quorum,
            voted,
            missing,
            reason,
        }
    }

    /// Check quorum for a specific block from a vote map.
    ///
    /// `votes` maps each validator to the block they voted for (or `None` for nil).
    /// `target_block` is the block we want to check quorum for.
    #[must_use]
    pub fn check_for_block(
        &self,
        votes: &HashMap<PublicKeyBytes, Option<Hash32>>,
        target_block: &Hash32,
    ) -> QuorumDiagnostic {
        let voters: Vec<PublicKeyBytes> = votes
            .iter()
            .filter(|(_, bid)| bid.as_ref() == Some(target_block))
            .map(|(pk, _)| pk.clone())
            .collect();
        self.check(&voters)
    }

    /// Get a human-readable summary of quorum status (for logging).
    #[must_use]
    pub fn summary(&self, voters: &[PublicKeyBytes]) -> String {
        let diag = self.check(voters);
        diag.to_string()
    }

    /// Can quorum still be reached if the given validators come online?
    /// Always returns `true` for a valid validator set (the total power is always ≥ threshold).
    #[must_use]
    pub fn can_reach_quorum(&self, _current_voters: &[PublicKeyBytes]) -> bool {
        self.vset.total_power() >= self.threshold
    }

    /// Minimum number of additional validators needed to reach quorum.
    ///
    /// This returns the smallest number of *distinct* validators that, if they voted,
    /// would bring the current power to at least the threshold. It picks the highest‑power
    /// missing validators first.
    #[must_use]
    pub fn validators_needed(&self, current_voters: &[PublicKeyBytes]) -> usize {
        let diag = self.check(current_voters);
        if diag.has_quorum {
            return 0;
        }

        let voter_set: HashSet<&PublicKeyBytes> = current_voters.iter().collect();
        let mut remaining: Vec<VotingPower> = self.vset.vals
            .iter()
            .filter(|v| !voter_set.contains(&v.pk))
            .map(|v| v.power)
            .collect();

        // Sort descending — we want the minimum count by taking the biggest first.
        remaining.sort_unstable_by(|a, b| b.cmp(a));

        let deficit = self.threshold.saturating_sub(diag.current_power);
        let mut accumulated = 0u64;
        for (i, p) in remaining.iter().enumerate() {
            accumulated += p;
            if accumulated >= deficit {
                return i + 1;
            }
        }

        // This should never happen because total power >= threshold.
        remaining.len() + 1
    }
}

// -----------------------------------------------------------------------------
// ValidatorConnectivity
// -----------------------------------------------------------------------------

/// P2P connectivity diagnostic for validators.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidatorConnectivity {
    pub total_validators: usize,
    pub connected_validators: usize,
    pub connected: Vec<String>,
    pub disconnected: Vec<String>,
    pub has_quorum_connectivity: bool,
}

impl fmt::Display for ValidatorConnectivity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "validators: {}/{} connected, quorum_ok={}",
            self.connected_validators,
            self.total_validators,
            self.has_quorum_connectivity
        )
    }
}

/// Check which validators are reachable from a set of connected peer public keys.
pub fn check_validator_connectivity(
    vset: &ValidatorSet,
    connected_pks: &[PublicKeyBytes],
) -> ValidatorConnectivity {
    let connected_set: HashSet<&PublicKeyBytes> = connected_pks.iter().collect();
    let threshold = (vset.total_power() * 2 / 3) + 1;

    let mut connected = Vec::new();
    let mut disconnected = Vec::new();
    let mut connected_power: VotingPower = 0;

    for val in &vset.vals {
        let pk_hex = hex::encode(&val.pk.0[..8]);
        if connected_set.contains(&val.pk) {
            connected.push(pk_hex);
            connected_power += val.power;
        } else {
            disconnected.push(pk_hex);
        }
    }

    ValidatorConnectivity {
        total_validators: vset.vals.len(),
        connected_validators: connected.len(),
        connected,
        disconnected,
        has_quorum_connectivity: connected_power >= threshold,
    }
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::Signer;
    use crate::crypto::ed25519::Ed25519Keypair;

    fn make_vset(n: usize) -> (ValidatorSet, Vec<PublicKeyBytes>) {
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
    fn test_quorum_1_of_1() {
        let (vset, pks) = make_vset(1);
        let qc = QuorumCalculator::new(&vset);
        assert_eq!(qc.threshold(), 1);
        assert!(qc.check(&pks[..1]).has_quorum);
        assert!(!qc.check(&[]).has_quorum);
    }

    #[test]
    fn test_quorum_3_of_3() {
        let (vset, pks) = make_vset(3);
        let qc = QuorumCalculator::new(&vset);
        assert_eq!(qc.threshold(), 3);
        assert!(!qc.check(&pks[..1]).has_quorum);
        assert!(!qc.check(&pks[..2]).has_quorum);
        assert!(qc.check(&pks[..3]).has_quorum);
    }

    #[test]
    fn test_quorum_3_of_4() {
        let (vset, pks) = make_vset(4);
        let qc = QuorumCalculator::new(&vset);
        assert_eq!(qc.threshold(), 3);
        assert!(!qc.check(&pks[..2]).has_quorum);
        assert!(qc.check(&pks[..3]).has_quorum);
        assert!(qc.check(&pks[..4]).has_quorum);
    }

    #[test]
    fn test_diagnostic_reason() {
        let (vset, pks) = make_vset(3);
        let qc = QuorumCalculator::new(&vset);
        let diag = qc.check(&pks[..1]);
        assert!(!diag.has_quorum);
        assert!(diag.reason.is_some());
        assert!(diag.reason.as_ref().unwrap().contains("missing_quorum"));
        assert_eq!(diag.voted.len(), 1);
        assert_eq!(diag.missing.len(), 2);
    }

    #[test]
    fn test_summary_format() {
        let (vset, pks) = make_vset(3);
        let qc = QuorumCalculator::new(&vset);
        let summary_ok = qc.summary(&pks);
        assert!(summary_ok.contains("quorum_ok"));
        let summary_fail = qc.summary(&pks[..1]);
        assert!(summary_fail.contains("NO_QUORUM"));
    }

    #[test]
    fn test_validators_needed() {
        let (vset, pks) = make_vset(4);
        let qc = QuorumCalculator::new(&vset);
        assert_eq!(qc.validators_needed(&pks), 0);
        assert_eq!(qc.validators_needed(&pks[..2]), 1);
        assert_eq!(qc.validators_needed(&pks[..1]), 2);
        assert_eq!(qc.validators_needed(&[]), 3);
    }

    #[test]
    fn test_connectivity() {
        let (vset, pks) = make_vset(3);
        let conn = check_validator_connectivity(&vset, &pks[..2]);
        assert_eq!(conn.total_validators, 3);
        assert_eq!(conn.connected_validators, 2);
        assert_eq!(conn.disconnected.len(), 1);
        assert!(!conn.has_quorum_connectivity);
    }

    #[test]
    fn test_weighted_quorum() {
        let mut seed1 = [0u8; 32];
        seed1[0] = 1;
        let mut seed2 = [0u8; 32];
        seed2[0] = 2;
        let mut seed3 = [0u8; 32];
        seed3[0] = 3;
        let pk1 = Ed25519Keypair::from_seed(seed1).public_key();
        let pk2 = Ed25519Keypair::from_seed(seed2).public_key();
        let pk3 = Ed25519Keypair::from_seed(seed3).public_key();
        let vset = ValidatorSet {
            vals: vec![
                Validator {
                    pk: pk1.clone(),
                    power: 10,
                },
                Validator {
                    pk: pk2.clone(),
                    power: 5,
                },
                Validator {
                    pk: pk3.clone(),
                    power: 5,
                },
            ],
        };
        let qc = QuorumCalculator::new(&vset);
        assert_eq!(qc.threshold(), 14);

        assert!(!qc.check(&[pk1.clone()]).has_quorum);
        assert!(qc.check(&[pk1.clone(), pk2.clone()]).has_quorum);
        assert!(!qc.check(&[pk2.clone(), pk3.clone()]).has_quorum);
    }

    #[test]
    fn test_display_impls() {
        let (vset, pks) = make_vset(3);
        let qc = QuorumCalculator::new(&vset);
        let diag = qc.check(&pks[..1]);
        let s = format!("{}", diag);
        assert!(s.contains("NO_QUORUM"));

        let conn = check_validator_connectivity(&vset, &pks[..2]);
        let s = format!("{}", conn);
        assert!(s.contains("connected"));
    }
}
