//! Genesis configuration for IONA v28.
//!
//! The validator set is determined by genesis.json, NOT hardcoded in the binary.
//! Any node, given the same genesis.json, knows exactly who the validators are.
//!
//! # Validation
//!
//! At node startup, the genesis file is loaded and validated:
//! - Chain ID must be non‑zero.
//! - At least one validator must be present.
//! - Validator seeds must be unique.
//! - All validator powers must be > 0.
//! - Protocol activations must be valid (non‑empty, contain PV=1 at height 0).
//!
//! The genesis hash is also computed and compared to the expected hash
//! (if stored in node_meta.json) to detect tampering.

use crate::consensus::validator_set::{Validator, ValidatorSet, VotingPower};
use crate::crypto::{PublicKeyBytes, Signer, ed25519::Ed25519Keypair};
use crate::protocol::version::{ProtocolActivation, default_activations};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::{fs, io, path::Path};

// -----------------------------------------------------------------------------
// Genesis configuration
// -----------------------------------------------------------------------------

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
    /// Optional: protocol activation schedule (if not provided, uses default).
    #[serde(default = "default_activations")]
    pub protocol_activations: Vec<ProtocolActivation>,
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

// -----------------------------------------------------------------------------
// Validation error
// -----------------------------------------------------------------------------

/// Error type for genesis validation.
#[derive(Debug, thiserror::Error)]
pub enum GenesisError {
    #[error("chain_id must be non‑zero")]
    ChainIdZero,
    #[error("genesis must contain at least one validator")]
    NoValidators,
    #[error("duplicate validator seed: {0}")]
    DuplicateSeed(u64),
    #[error("validator power must be > 0 (seed {0})")]
    ZeroPower(u64),
    #[error("invalid protocol activations: {0}")]
    InvalidActivations(String),
}

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

    /// Validate the genesis configuration.
    pub fn validate(&self) -> Result<(), GenesisError> {
        if self.chain_id == 0 {
            return Err(GenesisError::ChainIdZero);
        }
        if self.validators.is_empty() {
            return Err(GenesisError::NoValidators);
        }
        let mut seen = BTreeSet::new();
        for v in &self.validators {
            if !seen.insert(v.seed) {
                return Err(GenesisError::DuplicateSeed(v.seed));
            }
            if v.power == 0 {
                return Err(GenesisError::ZeroPower(v.seed));
            }
        }

        // Validate protocol activations
        if self.protocol_activations.is_empty() {
            return Err(GenesisError::InvalidActivations("empty activation list".into()));
        }
        let has_v1_at_zero = self.protocol_activations.iter().any(|a| {
            a.protocol_version == 1 && a.activation_height == Some(0)
        });
        if !has_v1_at_zero {
            return Err(GenesisError::InvalidActivations(
                "must include protocol_version=1 at height 0".into(),
            ));
        }
        // Check monotonicity of activation heights
        let mut prev_height: Option<u64> = None;
        for act in &self.protocol_activations {
            if let Some(h) = act.activation_height {
                if let Some(prev) = prev_height {
                    if h <= prev {
                        return Err(GenesisError::InvalidActivations(
                            format!("activation heights must be strictly increasing ({} <= {})", prev, h)
                        ));
                    }
                }
                prev_height = Some(h);
            }
        }

        Ok(())
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

    /// Compute the canonical hash of the genesis file (used for integrity checks).
    /// The hash is based on the JSON representation with canonical formatting.
    pub fn hash(&self) -> [u8; 32] {
        use sha2::{Digest, Sha256};
        let canonical = serde_json::to_string(self).expect("canonical serialization failed");
        let mut hasher = Sha256::new();
        hasher.update(canonical.as_bytes());
        let result = hasher.finalize();
        let mut out = [0u8; 32];
        out.copy_from_slice(&result);
        out
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
            protocol_activations: default_activations(),
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
        assert!(g.validate().is_ok());
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
        assert!(vset.contains(&vset.vals[0].pk));
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
        assert_eq!(g2.protocol_activations.len(), g.protocol_activations.len());
    }

    #[test]
    fn test_deterministic_keys() {
        let g = GenesisConfig::default_testnet();
        let vset1 = g.validator_set();
        let vset2 = g.validator_set();
        for (a, b) in vset1.vals.iter().zip(vset2.vals.iter()) {
            assert_eq!(a.pk, b.pk);
        }
    }

    #[test]
    fn test_quorum_thresholds() {
        let g1 = GenesisConfig {
            chain_id: 1,
            chain_name: "test".into(),
            validators: vec![GenesisValidator { seed: 1, power: 1, name: "v1".into() }],
            protocol_version: 1,
            initial_base_fee: 1,
            stake_each: 1000,
            protocol_activations: default_activations(),
        };
        assert_eq!(g1.quorum_threshold(), 1);

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
            protocol_activations: default_activations(),
        };
        assert_eq!(g4.quorum_threshold(), 3);
    }

    #[test]
    fn test_validation_errors() {
        let mut g = GenesisConfig::default_testnet();
        g.chain_id = 0;
        assert!(matches!(g.validate(), Err(GenesisError::ChainIdZero)));

        g.chain_id = 1;
        g.validators.clear();
        assert!(matches!(g.validate(), Err(GenesisError::NoValidators)));

        g.validators = vec![
            GenesisValidator { seed: 2, power: 1, name: "v2".into() },
            GenesisValidator { seed: 2, power: 1, name: "v2".into() },
        ];
        assert!(matches!(g.validate(), Err(GenesisError::DuplicateSeed(2))));

        g.validators = vec![GenesisValidator { seed: 2, power: 0, name: "v2".into() }];
        assert!(matches!(g.validate(), Err(GenesisError::ZeroPower(2))));
    }

    #[test]
    fn test_hash_deterministic() {
        let g1 = GenesisConfig::default_testnet();
        let g2 = GenesisConfig::default_testnet();
        assert_eq!(g1.hash(), g2.hash());
    }
}
