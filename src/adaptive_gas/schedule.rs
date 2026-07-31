//! Scheduled price updates for gas pricing.
//!
//! Provides flexible scheduling based on block count or time intervals,
//! with jitter to prevent thundering herd and integration with the pricing manager.

use crate::gas::{GasPricingManager, ResourceUsage};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::CancellationToken;
use tokio::time::sleep;
use tracing::{debug, error, info, trace, warn};

/// Update mode for price adjustments.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UpdateMode {
    /// Adjust every block (requires block height provider).
    PerBlock,
    /// Adjust every N blocks.
    EveryBlocks(u64),
    /// Adjust at fixed time interval.
    Every(Duration),
}

impl UpdateMode {
    /// Validate that the mode is reasonable.
    pub fn validate(&self) -> Result<(), String> {
        match self {
            Self::PerBlock => Ok(()),
            Self::EveryBlocks(n) if *n > 0 => Ok(()),
            Self::EveryBlocks(_) => Err("EveryBlocks count must be > 0".into()),
            Self::Every(d) if d.as_nanos() > 0 => Ok(()),
            Self::Every(_) => Err("Every duration must be > 0".into()),
        }
    }
}

/// Provides the current block height for block-based scheduling.
pub trait BlockHeightProvider: Send + Sync {
    fn current_block(&self) -> u64;
}

/// A simple provider that returns a fixed block number (useful for testing).
pub struct FixedBlockProvider {
    block: u64,
}

impl FixedBlockProvider {
    pub fn new(block: u64) -> Self {
        Self { block }
    }
    pub fn set_block(&mut self, block: u64) {
        self.block = block;
    }
}

impl BlockHeightProvider for FixedBlockProvider {
    fn current_block(&self) -> u64 {
        self.block
    }
}

/// Price schedule that tracks last update time and block.
#[derive(Debug)]
pub struct PriceSchedule {
    mode: UpdateMode,
    last_update_time: Instant,
    last_update_block: u64,
    /// Optional jitter to add to interval (fraction of interval, 0.0–1.0).
    jitter: f64,
}

impl PriceSchedule {
    /// Create a new schedule with the given mode and no jitter.
    pub fn new(mode: UpdateMode) -> Self {
        Self {
            mode,
            last_update_time: Instant::now(),
            last_update_block: 0,
            jitter: 0.0,
        }
    }

    /// Set jitter as a fraction of the interval (e.g., 0.1 = ±10%).
    /// Only meaningful for time-based modes.
    pub fn with_jitter(mut self, jitter: f64) -> Self {
        self.jitter = jitter.clamp(0.0, 1.0);
        self
    }

    /// Reset the schedule (set last update to now).
    pub fn reset(&mut self) {
        self.last_update_time = Instant::now();
        self.last_update_block = 0;
    }

    /// Reset only time, not block.
    pub fn reset_time(&mut self) {
        self.last_update_time = Instant::now();
    }

    /// Reset block counter.
    pub fn reset_block(&mut self, block: u64) {
        self.last_update_block = block;
    }

    /// Check if an update should occur, given current block height (if applicable).
    pub fn should_update(&self, current_block: Option<u64>) -> bool {
        match self.mode {
            UpdateMode::PerBlock => {
                if let Some(block) = current_block {
                    block != self.last_update_block
                } else {
                    // If no block provider, default to time-based: update at most once per second.
                    self.last_update_time.elapsed() >= Duration::from_secs(1)
                }
            }
            UpdateMode::EveryBlocks(n) => {
                if let Some(block) = current_block {
                    let diff = block.saturating_sub(self.last_update_block);
                    diff >= n
                } else {
                    // Fallback to time: check if interval passed.
                    let interval = Duration::from_secs(n * 5); // arbitrary mapping
                    self.last_update_time.elapsed() >= interval
                }
            }
            UpdateMode::Every(duration) => {
                let effective_duration = if self.jitter > 0.0 {
                    let jitter_secs = duration.as_secs_f64() * self.jitter;
                    let jitter_ms = (jitter_secs * 1000.0) as u64;
                    let mut rng = rand::thread_rng();
                    let offset = rand::Rng::gen_range(&mut rng, 0..=jitter_ms);
                    duration + Duration::from_millis(offset)
                } else {
                    duration
                };
                self.last_update_time.elapsed() >= effective_duration
            }
        }
    }

    /// Record that an update has been performed.
    pub fn mark_updated(&mut self, current_block: Option<u64>) {
        self.last_update_time = Instant::now();
        if let Some(block) = current_block {
            self.last_update_block = block;
        }
    }

    /// Get the time since last update.
    pub fn elapsed_since_update(&self) -> Duration {
        self.last_update_time.elapsed()
    }
}

/// Price updater that runs in the background and uses a pricing manager.
pub struct PriceUpdater {
    manager: Arc<GasPricingManager>,
    schedule: PriceSchedule,
    block_provider: Option<Box<dyn BlockHeightProvider>>,
    /// Optional demand provider (function returning ResourceUsage).
    demand_provider: Option<Box<dyn Fn() -> ResourceUsage + Send + Sync>>,
}

impl PriceUpdater {
    /// Create a new updater with a manager and schedule.
    pub fn new(manager: Arc<GasPricingManager>, schedule: PriceSchedule) -> Self {
        Self {
            manager,
            schedule,
            block_provider: None,
            demand_provider: None,
        }
    }

    /// Set a block height provider for block‑based modes.
    pub fn with_block_provider(mut self, provider: impl BlockHeightProvider + 'static) -> Self {
        self.block_provider = Some(Box::new(provider));
        self
    }

    /// Set a demand provider that returns current resource usage.
    /// If not set, a placeholder demand will be used.
    pub fn with_demand_provider<F>(mut self, provider: F) -> Self
    where
        F: Fn() -> ResourceUsage + Send + Sync + 'static,
    {
        self.demand_provider = Some(Box::new(provider));
        self
    }

    /// Run a single update cycle: check schedule, and if needed, fetch demand and adjust.
    pub async fn run_once(&mut self) -> Result<(), String> {
        let current_block = self.block_provider.as_ref().map(|p| p.current_block());
        if !self.schedule.should_update(current_block) {
            return Ok(());
        }

        // Get demand.
        let demand = if let Some(provider) = &self.demand_provider {
            provider()
        } else {
            // Default placeholder (50% usage).
            ResourceUsage {
                cpu_used: 50,
                io_used: 30,
                network_used: 20,
                storage_used: 10,
                target_cpu: 100,
                target_io: 60,
                target_network: 40,
                target_storage: 20,
            }
        };

        debug!("Running scheduled price adjustment");
        let result = self.manager.adjust(&demand);
        match result {
            Ok(()) => {
                self.schedule.mark_updated(current_block);
                info!("Price adjustment completed successfully");
                Ok(())
            }
            Err(e) => {
                error!("Price adjustment failed: {}", e);
                // Do not mark updated; we'll retry on next cycle.
                Err(e)
            }
        }
    }

    /// Start the background updater loop with cancellation support.
    pub async fn run_loop(mut self, cancellation_token: CancellationToken) {
        info!("Starting price updater loop with schedule: {:?}", self.schedule.mode);
        loop {
            // Determine next wake-up: if time-based, sleep until next interval.
            // For block-based, we sleep a short time and poll.
            let sleep_duration = match self.schedule.mode {
                UpdateMode::PerBlock | UpdateMode::EveryBlocks(_) => Duration::from_millis(100), // poll often
                UpdateMode::Every(duration) => {
                    // We can sleep until the next expected update time minus some slack.
                    let elapsed = self.schedule.elapsed_since_update();
                    if elapsed >= duration {
                        Duration::from_millis(0)
                    } else {
                        duration - elapsed
                    }
                }
            };

            tokio::select! {
                _ = sleep(sleep_duration) => {
                    // Run update.
                    if let Err(e) = self.run_once().await {
                        warn!("Update cycle failed: {}", e);
                    }
                }
                _ = cancellation_token.cancelled() => {
                    info!("Price updater loop cancelled, shutting down");
                    break;
                }
            }
        }
    }
}

/// Convenience function to spawn the updater as a tokio task.
pub fn spawn_updater(
    manager: Arc<GasPricingManager>,
    schedule: PriceSchedule,
    cancellation_token: CancellationToken,
) -> tokio::task::JoinHandle<()> {
    let updater = PriceUpdater::new(manager, schedule);
    tokio::spawn(updater.run_loop(cancellation_token))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::gas::GasPricingConfig;
    use std::sync::Arc;
    use tokio::time;

    fn test_manager() -> Arc<GasPricingManager> {
        let config = GasPricingConfig {
            enable_adaptive: true,
            ..Default::default()
        };
        Arc::new(GasPricingManager::new(config).unwrap())
    }

    #[test]
    fn test_schedule_validation() {
        assert!(UpdateMode::PerBlock.validate().is_ok());
        assert!(UpdateMode::EveryBlocks(5).validate().is_ok());
        assert!(UpdateMode::EveryBlocks(0).validate().is_err());
        assert!(UpdateMode::Every(Duration::from_secs(1)).validate().is_ok());
        assert!(UpdateMode::Every(Duration::ZERO).validate().is_err());
    }

    #[test]
    fn test_schedule_perblock() {
        let mut schedule = PriceSchedule::new(UpdateMode::PerBlock);
        let provider = FixedBlockProvider::new(10);
        let block = Some(provider.current_block());

        // Initially should update (last_block=0).
        assert!(schedule.should_update(block));
        schedule.mark_updated(block);
        assert!(!schedule.should_update(block)); // same block

        // New block.
        let provider2 = FixedBlockProvider::new(11);
        let block2 = Some(provider2.current_block());
        assert!(schedule.should_update(block2));
    }

    #[test]
    fn test_schedule_every_blocks() {
        let mut schedule = PriceSchedule::new(UpdateMode::EveryBlocks(3));
        let provider = FixedBlockProvider::new(5);
        let block = Some(provider.current_block());

        schedule.mark_updated(block); // last=5
        assert!(!schedule.should_update(Some(6))); // diff=1
        assert!(!schedule.should_update(Some(7))); // diff=2
        assert!(schedule.should_update(Some(8))); // diff=3
    }

    #[test]
    fn test_schedule_time_based() {
        let mut schedule = PriceSchedule::new(UpdateMode::Every(Duration::from_millis(50)));
        schedule.mark_updated(None);
        assert!(!schedule.should_update(None));
        std::thread::sleep(Duration::from_millis(60));
        assert!(schedule.should_update(None));
    }

    #[test]
    fn test_schedule_with_jitter() {
        let schedule = PriceSchedule::new(UpdateMode::Every(Duration::from_millis(100)))
            .with_jitter(0.2);
        // Hard to test precisely; just ensure it doesn't panic.
        let should = schedule.should_update(None);
        // It may be false initially, but after time passes it should be true.
    }

    #[tokio::test]
    async fn test_updater_run_once() {
        let manager = test_manager();
        let schedule = PriceSchedule::new(UpdateMode::PerBlock);
        let mut updater = PriceUpdater::new(manager.clone(), schedule);
        // No block provider, so it uses fallback (1s).
        // Run once should succeed.
        let result = updater.run_once().await;
        assert!(result.is_ok());
        // The manager should have adjusted prices (maybe).
    }

    #[tokio::test]
    async fn test_updater_loop_cancellation() {
        let manager = test_manager();
        let schedule = PriceSchedule::new(UpdateMode::Every(Duration::from_secs(60)));
        let cancellation_token = CancellationToken::new();

        let handle = spawn_updater(manager, schedule, cancellation_token.clone());
        // Let it run briefly.
        tokio::time::sleep(Duration::from_millis(50)).await;
        cancellation_token.cancel();
        // Wait for task to finish.
        handle.await.unwrap();
    }

    #[test]
    fn test_fixed_block_provider() {
        let mut provider = FixedBlockProvider::new(100);
        assert_eq!(provider.current_block(), 100);
        provider.set_block(200);
        assert_eq!(provider.current_block(), 200);
    }
}
