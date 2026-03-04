use crate::crypto::PublicKeyBytes;
use serde::{Deserialize, Serialize};

pub type VotingPower = u64;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Validator {
    pub pk: PublicKeyBytes,
    pub power: VotingPower,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ValidatorSet {
    pub vals: Vec<Validator>,
}

impl ValidatorSet {
    pub fn total_power(&self) -> VotingPower {
        self.vals.iter().map(|v| v.power).sum()
    }

    pub fn power_of(&self, pk: &PublicKeyBytes) -> VotingPower {
        self.vals.iter().find(|v| &v.pk == pk).map(|v| v.power).unwrap_or(0)
    }

    pub fn contains(&self, pk: &PublicKeyBytes) -> bool {
        self.power_of(pk) > 0
    }

    pub fn proposer_for(&self, height: u64, round: u32) -> &Validator {
        let n = self.vals.len();
        let idx = ((height as usize).wrapping_add(round as usize)) % n;
        &self.vals[idx]
    }
}


impl ValidatorSet {
    /// Deterministic hash of the validator set (used to bind snapshot attestations to a specific epoch).
    pub fn hash_hex(&self) -> String {
        // Canonical: sort by public key bytes
        let mut vals = self.vals.clone();
        vals.sort_by(|a,b| a.pk.0.cmp(&b.pk.0));
        let bytes = bincode::serialize(&vals).unwrap_or_default();
        let h = blake3::hash(&bytes);
        h.to_hex().to_string()
    }
}
