//! Genesis configuration for IONA v28.
//!
//! The validator set is determined by genesis.json, NOT hardcoded in the binary.
//! Any node, given the same genesis.json, knows exactly who the validators are.

use crate::consensus::validator_set::{Validator, ValidatorSet, VotingPower};
use crate::crypto::{PublicKeyBytes, Signer, ed25519::Ed25519Keypair};
use serde::{Deserialize, Serialize};
use std::{fs, io, path::Path};

/// On-disk genesis format.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GenesisConfig {
    pub chain_id: u64,
    /// Human-readable chain name (e.g. "iona-testnet-1").
    #[serde(default)]
    pub chain_name: String,
    /// Validators with their seeds and voting power.
    pub validators: Vec<GenesisValidator>,
    /// Initial protocol version (default 1).
    #[serde(default = "default_pv")]
    pub protocol_version: u32,
    /// Optional: initial base fee per gas.
    #[serde(default = "default_base_fee")]
    pub initial_base_fee: u64,
    /// Optional: stake per validator (for demo).
    #[serde(default = "default_stake")]
    pub stake_each: u64,
}

fn default_pv() -> u32 { 1 }
fn default_base_fee() -> u64 { 1 }
fn default_stake() -> u64 { 1000 }

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GenesisValidator {
    /// Deterministic seed (for demo key derivation).
    pub seed: u64,
    /// Voting power.
    #[serde(default = "default_power")]
    pub power: VotingPower,
    /// Optional human-readable name (e.g. "val2").
    #[serde(default)]
    pub name: String,
}

fn default_power() -> VotingPower { 1 }

impl GenesisConfig {
    /// Load genesis from a JSON file.
    pub fn load(path: impl AsRef<Path>) -> io::Result<Self> {
        let s = fs::read_to_string(path.as_ref())?;
        serde_json::from_str(&s)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("genesis.json parse: {e}")))
    }

    /// Save genesis to a JSON file.
    pub fn save(&self, path: impl AsRef<Path>) -> io::Result<()> {
        let out = serde_json::to_string_pretty(self)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("genesis.json encode: {e}")))?;
        fs::write(path.as_ref(), out)
    }

    /// Build a ValidatorSet from this genesis.
    pub fn validator_set(&self) -> ValidatorSet {
        let vals: Vec<Validator> = self.validators.iter().map(|gv| {
            let mut seed32 = [0u8; 32];
            seed32[..8].copy_from_slice(&gv.seed.to_le_bytes());
            let kp = Ed25519Keypair::from_seed(seed32);
            Validator {
                pk: kp.public_key(),
                power: gv.power,
            }
        }).collect();
        ValidatorSet { vals }
    }

    /// Check if a given public key is in the validator set.
    pub fn is_validator(&self, pk: &PublicKeyBytes) -> bool {
        self.validator_set().contains(pk)
    }

    /// Get the number of validators.
    pub fn validator_count(&self) -> usize {
        self.validators.len()
    }

    /// Compute the quorum threshold (2f+1).
    pub fn quorum_threshold(&self) -> VotingPower {
        let total: VotingPower = self.validators.iter().map(|v| v.power).sum();
        (total * 2 / 3) + 1
    }

    /// Create a default testnet genesis (3 validators: seeds 2, 3, 4).
    pub fn default_testnet() -> Self {
        Self {
            chain_id: 6126151,
            chain_name: "iona-testnet-1".into(),
            validators: vec![
                GenesisValidator { seed: 2, power: 1, name: "val2".into() },
                GenesisValidator { seed: 3, power: 1, name: "val3".into() },
                GenesisValidator { seed: 4, power: 1, name: "val4".into() },
            ],
            protocol_version: 1,
            initial_base_fee: 1,
            stake_each: 1000,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_testnet() {
        let g = GenesisConfig::default_testnet();
        assert_eq!(g.chain_id, 6126151);
        assert_eq!(g.validator_count(), 3);
        assert_eq!(g.quorum_threshold(), 3); // 2*3/3 + 1 = 3
    }

    #[test]
    fn test_validator_set_from_genesis() {
        let g = GenesisConfig::default_testnet();
        let vset = g.validator_set();
        assert_eq!(vset.vals.len(), 3);
        assert_eq!(vset.total_power(), 3);
    }

    #[test]
    fn test_is_validator() {
        let g = GenesisConfig::default_testnet();
        let vset = g.validator_set();
        // seed=2 should be a validator
        assert!(vset.contains(&vset.vals[0].pk));
        // random key should not be
        let rando = PublicKeyBytes(vec![99u8; 32]);
        assert!(!vset.contains(&rando));
    }

    #[test]
    fn test_genesis_roundtrip() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("genesis.json");

        let g = GenesisConfig::default_testnet();
        g.save(&path).unwrap();

        let g2 = GenesisConfig::load(&path).unwrap();
        assert_eq!(g2.chain_id, g.chain_id);
        assert_eq!(g2.validators.len(), g.validators.len());
        assert_eq!(g2.protocol_version, g.protocol_version);
    }

    #[test]
    fn test_deterministic_keys() {
        let g = GenesisConfig::default_testnet();
        let vset1 = g.validator_set();
        let vset2 = g.validator_set();
        // Same genesis → same keys
        for (a, b) in vset1.vals.iter().zip(vset2.vals.iter()) {
            assert_eq!(a.pk, b.pk);
        }
    }

    #[test]
    fn test_quorum_thresholds() {
        // 1 validator → threshold 1
        let g1 = GenesisConfig {
            chain_id: 1,
            chain_name: "test".into(),
            validators: vec![GenesisValidator { seed: 1, power: 1, name: "v1".into() }],
            protocol_version: 1,
            initial_base_fee: 1,
            stake_each: 1000,
        };
        assert_eq!(g1.quorum_threshold(), 1);

        // 4 validators → threshold 3
        let g4 = GenesisConfig {
            chain_id: 1,
            chain_name: "test".into(),
            validators: vec![
                GenesisValidator { seed: 1, power: 1, name: "v1".into() },
                GenesisValidator { seed: 2, power: 1, name: "v2".into() },
                GenesisValidator { seed: 3, power: 1, name: "v3".into() },
                GenesisValidator { seed: 4, power: 1, name: "v4".into() },
            ],
            protocol_version: 1,
            initial_base_fee: 1,
            stake_each: 1000,
        };
        assert_eq!(g4.quorum_threshold(), 3);
    }
}
