//! Appchain slot — leased security from IONA.
use serde::{Deserialize, Serialize};

pub const SLOT_DURATION_BLOCKS:  u64 = 1_000_000;  // ~11.5 days at 1s/block
pub const MAX_SLOTS:             usize = 100;
pub const MIN_BOND_PER_SLOT:     u64 = 1_000_000;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppchainSlot {
    pub slot_id:      u64,
    pub chain_id:     u64,
    pub lessee:       String,   // appchain operator address
    pub bond:         u64,      // IONA bonded for this slot
    pub start_height: u64,
    pub end_height:   u64,
    pub is_active:    bool,
}

#[derive(Debug, Default, Serialize, Deserialize)]
pub struct SlotAuction {
    pub slots: Vec<AppchainSlot>,
    pub next_slot_id: u64,
    pub total_bonded: u64,
}

impl SlotAuction {
    pub fn lease_slot(&mut self, chain_id: u64, lessee: String, bond: u64, current_height: u64) -> Result<u64, &'static str> {
        if bond < MIN_BOND_PER_SLOT { return Err("insufficient bond"); }
        if self.slots.iter().filter(|s| s.is_active).count() >= MAX_SLOTS { return Err("all slots occupied"); }
        let slot_id = self.next_slot_id;
        self.next_slot_id += 1;
        self.total_bonded += bond;
        self.slots.push(AppchainSlot {
            slot_id, chain_id, lessee, bond,
            start_height: current_height,
            end_height:   current_height + SLOT_DURATION_BLOCKS,
            is_active: true,
        });
        tracing::info!(slot_id, chain_id, bond, "Appchain slot leased");
        Ok(slot_id)
    }
    pub fn active_slots(&self) -> Vec<&AppchainSlot> {
        self.slots.iter().filter(|s| s.is_active).collect()
    }
    pub fn expire_slots(&mut self, current_height: u64) {
        for slot in &mut self.slots {
            if slot.is_active && current_height > slot.end_height {
                slot.is_active = false;
                self.total_bonded = self.total_bonded.saturating_sub(slot.bond);
            }
        }
    }
}
