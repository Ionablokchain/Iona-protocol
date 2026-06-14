//! Parachain registry.
//!
//! Maintains the set of all registered parachains, their metadata, and
//! current status. Used by the IONA consensus to know which parachains
//! are allowed to produce blocks.

use crate::ParachainError;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// Status of a parachain in the registry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ParachainStatus {
    /// Registered but not yet active (waiting for slot lease)
    Registered,
    /// Active and producing blocks
    Active,
    /// Paused (e.g., slashed or out of funds)
    Paused,
    /// Deregistered (can be re‑registered)
    Deregistered,
}

/// Information about a registered parachain.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ParachainInfo {
    pub id: u32,
    pub name: String,
    pub owner: String,   // IONA address of the owner
    pub status: ParachainStatus,
    pub slot_id: Option<u64>,
    pub validation_code_hash: [u8; 32],
    pub registered_at: u64,   // block height
    pub deposit: u64,
}

/// Registry of all parachains.
pub struct ParachainRegistry {
    chains: BTreeMap<u32, ParachainInfo>,
    next_id: u32,
}

impl ParachainRegistry {
    pub fn new() -> Self {
        Self {
            chains: BTreeMap::new(),
            next_id: 1,
        }
    }

    /// Register a new parachain (generates a new ID).
    pub fn register(
        &mut self,
        name: &str,
        owner: &str,
        validation_code_hash: [u8; 32],
        deposit: u64,
        block_height: u64,
    ) -> u32 {
        let id = self.next_id;
        self.next_id += 1;
        let info = ParachainInfo {
            id,
            name: name.to_string(),
            owner: owner.to_string(),
            status: ParachainStatus::Registered,
            slot_id: None,
            validation_code_hash,
            registered_at: block_height,
            deposit,
        };
        self.chains.insert(id, info);
        id
    }

    /// Activate a parachain (assign a slot to it).
    pub fn activate(&mut self, id: u32, slot_id: u64) -> ParachainResult<()> {
        let info = self.chains.get_mut(&id).ok_or(ParachainError::NotFound(id))?;
        if info.status != ParachainStatus::Registered {
            return Err(ParachainError::Sovereign("chain not in registered state".into()));
        }
        info.status = ParachainStatus::Active;
        info.slot_id = Some(slot_id);
        Ok(())
    }

    /// Pause a parachain (e.g., after slashing).
    pub fn pause(&mut self, id: u32) -> ParachainResult<()> {
        let info = self.chains.get_mut(&id).ok_or(ParachainError::NotFound(id))?;
        info.status = ParachainStatus::Paused;
        Ok(())
    }

    /// Deregister a parachain (slashing the deposit).
    pub fn deregister(&mut self, id: u32) -> ParachainResult<()> {
        let info = self.chains.get_mut(&id).ok_or(ParachainError::NotFound(id))?;
        info.status = ParachainStatus::Deregistered;
        Ok(())
    }

    /// Get a reference to a parachain info.
    pub fn get(&self, id: u32) -> Option<&ParachainInfo> {
        self.chains.get(&id)
    }

    /// Get a mutable reference.
    pub fn get_mut(&mut self, id: u32) -> Option<&mut ParachainInfo> {
        self.chains.get_mut(&id)
    }

    /// List all active parachains.
    pub fn active(&self) -> Vec<&ParachainInfo> {
        self.chains.values().filter(|c| c.status == ParachainStatus::Active).collect()
    }
}

impl Default for ParachainRegistry {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_registration() {
        let mut reg = ParachainRegistry::new();
        let id = reg.register("mychain", "owner", [0u8; 32], 10000, 100);
        assert_eq!(reg.get(id).unwrap().status, ParachainStatus::Registered);
        reg.activate(id, 5).unwrap();
        assert_eq!(reg.get(id).unwrap().status, ParachainStatus::Active);
        assert_eq!(reg.get(id).unwrap().slot_id, Some(5));
    }
}
