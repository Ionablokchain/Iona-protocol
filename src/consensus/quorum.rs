use crate::consensus::validator_set::{ValidatorSet, VotingPower};
use crate::crypto::PublicKeyBytes;
use crate::types::Hash32;
use std::collections::HashMap;

#[derive(Clone, Debug, Default)]
pub struct VoteTally {
    pub per_block: HashMap<Option<Hash32>, VotingPower>,
}

impl VoteTally {
    pub fn add_vote(&mut self, vset: &ValidatorSet, voter: &PublicKeyBytes, block_id: &Option<Hash32>) {
        let p = vset.power_of(voter);
        *self.per_block.entry(block_id.clone()).or_insert(0) += p;
    }

    pub fn best(&self) -> Option<(Option<Hash32>, VotingPower)> {
        self.per_block.iter().max_by_key(|(_, p)| **p).map(|(k, p)| (k.clone(), *p))
    }
}

pub fn quorum_threshold(total: VotingPower) -> VotingPower {
    (total * 2 / 3) + 1
}
