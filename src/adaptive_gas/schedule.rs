//! Scheduled price updates for gas pricing.

use crate::gas::{GasPricingConfig, ResourceType, ResourceUsage};
use std::time::{Duration, Instant};

/// Update mode for price adjustments.
#[derive(Debug, Clone, Copy)]
pub enum UpdateMode {
    /// Adjust every block.
    PerBlock,
    /// Adjust every N blocks.
    EveryBlocks(u64),
    /// Adjust at fixed time interval.
    Every(Duration),
}

/// Price schedule that triggers updates at specified intervals.
#[derive(Debug)]
pub struct PriceSchedule {
    mode: UpdateMode,
    last_update: Instant,
}

impl PriceSchedule {
    pub fn new(mode: UpdateMode) -> Self {
        Self {
            mode,
            last_update: Instant::now(),
        }
    }

    pub fn should_update(&self) -> bool {
        match self.mode {
            UpdateMode::PerBlock => true,
            UpdateMode::EveryBlocks(n) => {
                // Placeholder: in production, we'd track block count.
                // For now, we just return true every call.
                true
            }
            UpdateMode::Every(duration) => {
                self.last_update.elapsed() >= duration
            }
        }
    }

    pub fn reset(&mut self) {
        self.last_update = Instant::now();
    }
}

/// Price updater that runs in the background.
pub struct PriceUpdater {
    config: GasPricingConfig,
    schedule: PriceSchedule,
}

impl PriceUpdater {
    pub fn new(config: GasPricingConfig, mode: UpdateMode) -> Self {
        Self {
            config,
            schedule: PriceSchedule::new(mode),
        }
    }

    pub fn should_run(&self) -> bool {
        self.schedule.should_update()
    }

    pub fn run(&mut self, demand: &ResourceUsage) -> Result<Vec<(ResourceType, u64, u64)>, String> {
        // Placeholder: in production, we would call the pricing manager.
        // Here we just compute adjustments locally.
        let mut adjustments = Vec::new();
        // Simulated adjustment.
        self.schedule.reset();
        Ok(adjustments)
    }
}
