//! Vote tallying and quorum calculation for consensus.
//!
//! This module provides utilities to aggregate votes from validators
//! and determine when a quorum has been reached.
//!
//! # Example
//!
//! ```
//! use iona::consensus::quorum::{VoteTally, quorum_threshold};
//! use iona::consensus::validator_set::{ValidatorSet, Validator};
//! use iona::crypto::PublicKeyBytes;
//! use iona::types::Hash32;
//!
//! let vset = ValidatorSet {
//!     vals: vec![
//!         Validator { pk: PublicKeyBytes(vec![1; 32]), power: 10 },
//!         Validator { pk: PublicKeyBytes(vec![2; 32]), power: 20 },
//!     ],
//! };
//! let mut tally = VoteTally::default();
//! let block_id = Some(Hash32([1; 32]));
//! tally.add_vote(&vset, &PublicKeyBytes(vec![1; 32]), &block_id);
//! let (_, power) = tally.best().unwrap();
//! assert_eq!(power, 10);
//! assert_eq!(quorum_threshold(30), 21);
//! ```

use crate::consensus::validator_set::{ValidatorSet, VotingPower};
use crate::crypto::PublicKeyBytes;
use crate::types::Hash32;
use std::collections::HashMap;

// -----------------------------------------------------------------------------
// Constants
// -----------------------------------------------------------------------------

/// Numerator of the quorum fraction (2/3 of total voting power).
pub const QUORUM_NUMERATOR: u64 = 2;

/// Denominator of the quorum fraction (3).
pub const QUORUM_DENOMINATOR: u64 = 3;

// -----------------------------------------------------------------------------
// VoteTally
// -----------------------------------------------------------------------------

/// Tally of votes, grouped by the block they vote for.
///
/// Used to compute the total voting power that has voted for each block,
/// and to determine which block (if any) has reached a quorum.
#[derive(Clone, Debug, Default)]
pub struct VoteTally {
    /// Maps a block ID (or `None` for nil votes) to the total voting power
    /// that has cast a vote for that option.
    pub per_block: HashMap<Option<Hash32>, VotingPower>,
}

impl VoteTally {
    /// Add a vote from a validator to the tally.
    ///
    /// # Arguments
    /// * `vset` – the current validator set (to look up the validator's power).
    /// * `voter` – the public key of the validator casting the vote.
    /// * `block_id` – the block ID they are voting for (or `None` for a nil vote).
    pub fn add_vote(
        &mut self,
        vset: &ValidatorSet,
        voter: &PublicKeyBytes,
        block_id: &Option<Hash32>,
    ) {
        let power = vset.power_of(voter);
        *self.per_block.entry(block_id.clone()).or_insert(0) += power;
    }

    /// Find the block with the highest total voting power.
    ///
    /// Returns a tuple `(block_id, power)` for the block that has the most
    /// votes. If the tally is empty, returns `None`.
    pub fn best(&self) -> Option<(Option<Hash32>, VotingPower)> {
        self.per_block
            .iter()
            .max_by_key(|(_, power)| **power)
            .map(|(block_id, power)| (block_id.clone(), *power))
    }

    /// Check if a specific block has reached the given quorum threshold.
    ///
    /// # Arguments
    /// * `block_id` – the block to check (or `None` for nil votes).
    /// * `threshold` – the minimum voting power required (e.g., from `quorum_threshold`).
    pub fn has_quorum(&self, block_id: &Option<Hash32>, threshold: VotingPower) -> bool {
        self.per_block.get(block_id).copied().unwrap_or(0) >= threshold
    }

    /// Get the total voting power tallied so far.
    pub fn total_power(&self) -> VotingPower {
        self.per_block.values().sum()
    }

    /// Clear the tally.
    pub fn clear(&mut self) {
        self.per_block.clear();
    }
}

// -----------------------------------------------------------------------------
// Quorum calculation
// -----------------------------------------------------------------------------

/// Compute the quorum threshold for a given total validator power.
///
/// In Tendermint‑style consensus, a quorum is reached when more than 2/3
/// of the total voting power has voted for the same block.
///
/// # Formula
/// ```text
/// threshold = (total * QUORUM_NUMERATOR) / QUORUM_DENOMINATOR + 1
/// ```
///
/// # Examples
/// ```
/// use iona::consensus::quorum::quorum_threshold;
/// assert_eq!(quorum_threshold(1), 1);
/// assert_eq!(quorum_threshold(3), 3);
/// assert_eq!(quorum_threshold(4), 3);
/// ```
pub fn quorum_threshold(total: VotingPower) -> VotingPower {
    (total * QUORUM_NUMERATOR / QUORUM_DENOMINATOR) + 1
}

/// Extension: compute quorum threshold directly from a validator set.
impl ValidatorSet {
    /// Returns the quorum threshold (minimum voting power required) for this validator set.
    pub fn quorum_threshold(&self) -> VotingPower {
        quorum_threshold(self.total_power())
    }
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::consensus::validator_set::{Validator, ValidatorSet};

    fn test_vset() -> ValidatorSet {
        ValidatorSet {
            vals: vec![
                Validator { pk: PublicKeyBytes(vec![1u8; 32]), power: 1 },
                Validator { pk: PublicKeyBytes(vec![2u8; 32]), power: 1 },
                Validator { pk: PublicKeyBytes(vec![3u8; 32]), power: 1 },
            ],
        }
    }

    #[test]
    fn test_vote_tally_basic() {
        let vset = test_vset();
        let mut tally = VoteTally::default();
        let block_a = Some(Hash32([0xAA; 32]));
        let block_b = Some(Hash32([0xBB; 32]));

        tally.add_vote(&vset, &PublicKeyBytes(vec![1u8; 32]), &block_a);
        tally.add_vote(&vset, &PublicKeyBytes(vec![2u8; 32]), &block_a);
        tally.add_vote(&vset, &PublicKeyBytes(vec![3u8; 32]), &block_b);

        assert_eq!(tally.best(), Some((block_a.clone(), 2)));
        assert!(!tally.has_quorum(&block_a, 3));
        assert_eq!(tally.total_power(), 3);
    }

    #[test]
    fn test_nil_votes() {
        let vset = test_vset();
        let mut tally = VoteTally::default();
        let nil: Option<Hash32> = None;

        tally.add_vote(&vset, &PublicKeyBytes(vec![1u8; 32]), &nil);
        tally.add_vote(&vset, &PublicKeyBytes(vec![2u8; 32]), &nil);
        tally.add_vote(&vset, &PublicKeyBytes(vec![3u8; 32]), &nil);

        assert_eq!(tally.best(), Some((nil.clone(), 3)));
        assert!(tally.has_quorum(&nil, 2));
    }

    #[test]
    fn test_quorum_threshold() {
        assert_eq!(quorum_threshold(1), 1);
        assert_eq!(quorum_threshold(2), 2);
        assert_eq!(quorum_threshold(3), 3);
        assert_eq!(quorum_threshold(4), 3);
        assert_eq!(quorum_threshold(5), 4);
        assert_eq!(quorum_threshold(100), 67);
    }

    #[test]
    fn test_vset_quorum_threshold() {
        let vset = test_vset();
        assert_eq!(vset.quorum_threshold(), (3 * 2 / 3) + 1);
    }

    #[test]
    fn test_clear() {
        let vset = test_vset();
        let mut tally = VoteTally::default();
        tally.add_vote(&vset, &PublicKeyBytes(vec![1u8; 32]), &Some(Hash32([1; 32])));
        assert_eq!(tally.total_power(), 1);
        tally.clear();
        assert_eq!(tally.total_power(), 0);
        assert!(tally.per_block.is_empty());
    }
}
