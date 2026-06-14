//! Slot leasing for parachains.
//!
//! Parachains must obtain a slot lease to produce blocks. Slots are allocated
//! via a simple auction mechanism (first‑price, blind bid). Each lease lasts
//! for a fixed number of blocks.

use crate::ParachainError;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::time::{Duration, SystemTime};

/// Status of a slot.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SlotStatus {
    Available,
    Leased {
        parachain_id: u32,
        lease_start_block: u64,
        lease_end_block: u64,
    },
}

/// A single block production slot.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Slot {
    pub id: u64,
    pub status: SlotStatus,
    pub base_price: u64, // minimum bid in native tokens
}

/// A lease agreement for a parachain.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SlotLease {
    pub slot_id: u64,
    pub parachain_id: u32,
    pub start_block: u64,
    pub end_block: u64,
    pub price_paid: u64,
}

/// Manages slot allocation and leasing.
pub struct SlotManager {
    slots: BTreeMap<u64, Slot>,
    leases: BTreeMap<u64, SlotLease>, // slot_id -> lease
    next_slot_id: u64,
}

impl SlotManager {
    /// Create a new slot manager with a range of available slots.
    pub fn new(first_slot_id: u64, num_slots: u64, base_price: u64) -> Self {
        let mut slots = BTreeMap::new();
        for i in 0..num_slots {
            let id = first_slot_id + i;
            slots.insert(id, Slot {
                id,
                status: SlotStatus::Available,
                base_price,
            });
        }
        Self {
            slots,
            leases: BTreeMap::new(),
            next_slot_id: first_slot_id + num_slots,
        }
    }

    /// Create additional slots dynamically.
    pub fn add_slot(&mut self, base_price: u64) -> u64 {
        let id = self.next_slot_id;
        self.next_slot_id += 1;
        self.slots.insert(id, Slot {
            id,
            status: SlotStatus::Available,
            base_price,
        });
        id
    }

    /// Lease a slot for a parachain for a given number of blocks.
    /// Returns the slot ID on success.
    pub fn lease_slot(
        &mut self,
        parachain_id: u32,
        start_block: u64,
        duration_blocks: u64,
        bid: u64,
    ) -> ParachainResult<u64> {
        // Find first available slot whose base_price <= bid
        let (slot_id, slot) = self.slots
            .iter_mut()
            .find(|(_, s)| matches!(s.status, SlotStatus::Available) && s.base_price <= bid)
            .ok_or(ParachainError::SlotNotAvailable(0))?;

        let end_block = start_block
            .checked_add(duration_blocks)
            .ok_or(ParachainError::InvalidSlotDuration(duration_blocks))?;

        let lease = SlotLease {
            slot_id: *slot_id,
            parachain_id,
            start_block,
            end_block,
            price_paid: bid,
        };

        slot.status = SlotStatus::Leased {
            parachain_id,
            lease_start_block: start_block,
            lease_end_block: end_block,
        };
        self.leases.insert(*slot_id, lease);
        Ok(*slot_id)
    }

    /// Release a slot (called when a parachain deregisters or lease expires).
    pub fn release_slot(&mut self, slot_id: u64) -> ParachainResult<()> {
        let slot = self.slots.get_mut(&slot_id).ok_or(ParachainError::NotFound(slot_id as u32))?;
        match slot.status {
            SlotStatus::Leased { .. } => {
                slot.status = SlotStatus::Available;
                self.leases.remove(&slot_id);
                Ok(())
            }
            SlotStatus::Available => Err(ParachainError::SlotNotAvailable(slot_id)),
        }
    }

    /// Get the slot currently leased by a parachain, if any.
    pub fn slot_of(&self, parachain_id: u32) -> Option<&SlotLease> {
        self.leases.values().find(|l| l.parachain_id == parachain_id)
    }

    /// Check if a slot is currently leased.
    pub fn is_leased(&self, slot_id: u64) -> bool {
        matches!(self.slots.get(&slot_id).map(|s| &s.status), Some(SlotStatus::Leased { .. }))
    }

    /// Update slot status based on current block height (call at block boundaries).
    pub fn prune_expired_leases(&mut self, current_block: u64) {
        let expired: Vec<u64> = self.leases
            .iter()
            .filter(|(_, lease)| lease.end_block <= current_block)
            .map(|(slot_id, _)| *slot_id)
            .collect();
        for slot_id in expired {
            let _ = self.release_slot(slot_id);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_lease_and_release() {
        let mut mgr = SlotManager::new(1, 10, 1000);
        let slot_id = mgr.lease_slot(42, 100, 50, 1500).unwrap();
        assert!(mgr.is_leased(slot_id));
        assert_eq!(mgr.slot_of(42).unwrap().slot_id, slot_id);
        mgr.release_slot(slot_id).unwrap();
        assert!(!mgr.is_leased(slot_id));
    }

    #[test]
    fn test_insufficient_bid() {
        let mut mgr = SlotManager::new(1, 1, 1000);
        let res = mgr.lease_slot(42, 100, 50, 500);
        assert!(matches!(res, Err(ParachainError::SlotNotAvailable(_))));
    }

    #[test]
    fn test_prune_expired() {
        let mut mgr = SlotManager::new(1, 1, 1000);
        mgr.lease_slot(42, 100, 50, 1000).unwrap();
        mgr.prune_expired_leases(150); // end_block = 150
        assert!(!mgr.is_leased(1));
    }
}
