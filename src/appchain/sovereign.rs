//! Sovereign chain state management.
//!
//! Each parachain is a sovereign chain that maintains its own state (head,
//! validation code). IONA validators verify proofs of the sovereign chain's
//! state transitions.

use crate::ParachainError;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// Status of a sovereign chain.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SovereigntyStatus {
    /// Chain is active and producing blocks.
    Active,
    /// Chain is paused (e.g., out of funds or after misbehaviour).
    Paused,
    /// Chain is being retired.
    Retired,
}

/// A sovereign chain (parachain) registered on IONA.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SovereignChain {
    pub id: u32,
    pub name: String,
    /// Current block header hash (32 bytes)
    pub head: [u8; 32],
    /// Validation code hash (for state transition verification)
    pub validation_code_hash: [u8; 32],
    /// Current status
    pub status: SovereigntyStatus,
    /// Number of blocks produced (height)
    pub height: u64,
    /// Deposit locked in IONA (collateral)
    pub deposit: u64,
    /// Last time this chain produced a block (Unix timestamp)
    pub last_block_time: u64,
}

impl SovereignChain {
    /// Create a new sovereign chain registration request.
    pub fn new(id: u32, name: &str, validation_code_hash: [u8; 32], deposit: u64) -> Self {
        Self {
            id,
            name: name.to_string(),
            head: [0u8; 32],
            validation_code_hash,
            status: SovereigntyStatus::Active,
            height: 0,
            deposit,
            last_block_time: 0,
        }
    }

    /// Update the chain's head and height (called after verifying a proof).
    pub fn update_head(&mut self, new_head: [u8; 32]) -> ParachainResult<()> {
        if self.status != SovereigntyStatus::Active {
            return Err(ParachainError::Sovereign("chain not active".into()));
        }
        self.head = new_head;
        self.height = self.height.checked_add(1).ok_or(ParachainError::Sovereign("height overflow".into()))?;
        self.last_block_time = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        Ok(())
    }

    /// Pause the chain (slash if needed).
    pub fn pause(&mut self) {
        self.status = SovereigntyStatus::Paused;
    }

    /// Reactivate the chain.
    pub fn activate(&mut self) {
        self.status = SovereigntyStatus::Active;
    }

    /// Retire the chain.
    pub fn retire(&mut self) {
        self.status = SovereigntyStatus::Retired;
    }
}

/// Manage all sovereign chains.
pub struct SovereignRegistry {
    chains: BTreeMap<u32, SovereignChain>,
}

impl SovereignRegistry {
    pub fn new() -> Self {
        Self { chains: BTreeMap::new() }
    }

    /// Register a new sovereign chain.
    pub fn register(&mut self, chain: SovereignChain) -> ParachainResult<()> {
        if self.chains.contains_key(&chain.id) {
            return Err(ParachainError::AlreadyExists(chain.id));
        }
        self.chains.insert(chain.id, chain);
        Ok(())
    }

    /// Get a mutable reference to a chain.
    pub fn get_mut(&mut self, id: u32) -> Option<&mut SovereignChain> {
        self.chains.get_mut(&id)
    }

    /// Get a reference to a chain.
    pub fn get(&self, id: u32) -> Option<&SovereignChain> {
        self.chains.get(&id)
    }

    /// Remove a chain (after retirement).
    pub fn remove(&mut self, id: u32) -> Option<SovereignChain> {
        self.chains.remove(&id)
    }

    /// List all active chains.
    pub fn active_chains(&self) -> Vec<&SovereignChain> {
        self.chains.values().filter(|c| c.status == SovereigntyStatus::Active).collect()
    }

    /// Update a chain's head (convenience).
    pub fn update_head(&mut self, id: u32, head: [u8; 32]) -> ParachainResult<()> {
        let chain = self.get_mut(id).ok_or(ParachainError::NotFound(id))?;
        chain.update_head(head)
    }
}

impl Default for SovereignRegistry {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sovereign_lifecycle() {
        let mut reg = SovereignRegistry::new();
        let chain = SovereignChain::new(1, "testchain", [0u8; 32], 10000);
        reg.register(chain).unwrap();
        let head = [1u8; 32];
        reg.update_head(1, head).unwrap();
        let chain = reg.get(1).unwrap();
        assert_eq!(chain.head, head);
        assert_eq!(chain.height, 1);
    }
}
