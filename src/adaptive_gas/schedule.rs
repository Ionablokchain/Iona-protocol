//! Scheduled price updates for gas pricing.
//!
//! Provides flexible scheduling based on block count or time intervals,
//! with deterministic jitter to prevent thundering herd, and integration
//! with the pricing manager.
//!
//! # Jitter semantics
//!
//! Jitter adds a **deterministic per-interval offset** to the base
//! interval. The offset is derived from a counter and the base duration,
//! not from a wall-clock source, so:
//!
//! - two consecutive calls to [`PriceSchedule::should_update`] return the
//!   same answer (no busy loop),
//! - [`PriceSchedule::time_until_next`] reports the true remaining time
//!   including jitter,
//! - tests are reproducible.
//!
//! The offset is **always additive**: an interval of `d` fires between
//! `d` and `d × (1 + jitter)` after the previous update. The doc of
//! [`PriceSchedule::with_jitter`] documents this.
//!
//! # Async / sync
//!
//! [`PriceUpdater::run_once`] is async and uses
//! [`GasPricingManager::adjust_async`] (non-blocking retry backoff). The
//! previous implementation called the **synchronous** `adjust`, which
//! used `std::thread::sleep` in its retry loop and blocked the tokio
//! worker thread.
//!
//! # Misconfiguration
//!
//! Block-based modes (`PerBlock`, `EveryBlocks`) require a
//! [`BlockHeightProvider`]. [`PriceUpdater::new`] accepts a schedule
//! without one (the provider is set via the builder), but
//! [`PriceUpdater::run_once`] returns
//! [`UpdateError::MissingBlockProvider`] until a provider is set, and
//! [`PriceUpdater::run_loop`] logs and exits cleanly.

use crate::gas::{GasPricingManager, ResourceUsage};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use thiserror::Error;
use tokio::sync::CancellationToken;
use tokio::time::sleep;
use tracing::{debug, error, info, trace, warn};

// ── Limits ────────────────────────────────────────────────────────────────

/// Minimum effective interval for a time-based schedule.
///
/// `Every(d)` with `d < MIN_INTERVAL` is clamped to `MIN_INTERVAL` at
/// runtime; `UpdateMode::validate` still rejects a zero duration so the
/// misconfiguration is visible.
pub const MIN_INTERVAL: Duration = Duration::from_millis(1);

/// Default poll interval for block-based modes.
pub const DEFAULT_POLL_INTERVAL: Duration = Duration::from_millis(100);

/// Default backoff after a failed adjustment.
pub const DEFAULT_BACKOFF: Duration = Duration::from_secs(5);

// ── Errors ────────────────────────────────────────────────────────────────

/// Why [`UpdateMode::validate`] rejected a mode.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum UpdateModeError {
    #[error("EveryBlocks count must be > 0")]
    ZeroBlockCount,
    #[error("Every duration must be > 0")]
    ZeroDuration,
}

/// Errors from the price updater.
#[derive(Debug, Error)]
pub enum UpdateError {
    #[error("invalid update mode: {0}")]
    InvalidMode(#[from] UpdateModeError),

    #[error("block-based schedule requires a BlockHeightProvider; use with_block_provider")]
    MissingBlockProvider,

    #[error("price adjustment failed after retries: {0}")]
    AdjustFailed(String),
}

/// Outcome of a single [`PriceUpdater::run_once`] call.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UpdateOutcome {
    /// A price adjustment was applied.
    Applied,
    /// The schedule indicated no update was due.
    NotDue,
}

// ── Update mode ───────────────────────────────────────────────────────────

/// Update mode for price adjustments.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UpdateMode {
    /// Adjust every block. Requires a [`BlockHeightProvider`].
    PerBlock,
    /// Adjust every N blocks. Requires a [`BlockHeightProvider`].
    EveryBlocks(u64),
    /// Adjust at fixed time interval.
    Every(Duration),
}

impl UpdateMode {
    /// Validate the mode.
    pub fn validate(&self) -> Result<(), UpdateModeError> {
        match self {
            Self::PerBlock => Ok(()),
            Self::EveryBlocks(0) => Err(UpdateModeError::ZeroBlockCount),
            Self::EveryBlocks(_) => Ok(()),
            Self::Every(d) if d.is_zero() => Err(UpdateModeError::ZeroDuration),
            Self::Every(_) => Ok(()),
        }
    }

    /// Whether this mode requires a [`BlockHeightProvider`].
    #[must_use]
    pub fn requires_block_provider(&self) -> bool {
        matches!(self, Self::PerBlock | Self::EveryBlocks(_))
    }
}

// ── Block providers ───────────────────────────────────────────────────────

/// Provides the current block height for block-based scheduling.
pub trait BlockHeightProvider: Send + Sync {
    fn current_block(&self) -> u64;
}

/// A provider that returns a fixed block number; use
/// [`set_block`](Self::set_block) to advance it. Not thread-safe by
/// design — construct it directly in tests. For a shared mutable
/// provider, use [`SharedBlockProvider`].
pub struct FixedBlockProvider {
    block: u64,
}

impl FixedBlockProvider {
    #[must_use]
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

/// A thread-safe provider backed by an `Arc<AtomicU64>`. The caller holds
/// a handle and updates the block from wherever the block is produced.
#[derive(Debug, Clone)]
pub struct SharedBlockProvider {
    block: Arc<AtomicU64>,
}

impl SharedBlockProvider {
    #[must_use]
    pub fn new(initial: u64) -> Self {
        Self {
            block: Arc::new(AtomicU64::new(initial)),
        }
    }

    /// Update the current block.
    pub fn set(&self, value: u64) {
        self.block.store(value, Ordering::Release);
    }

    /// A second handle to the same underlying block counter. Useful when
    /// the provider is boxed into a [`PriceUpdater`] and the caller wants
    /// to advance the block.
    #[must_use]
    pub fn clone_handle(&self) -> Self {
        Self {
            block: self.block.clone(),
        }
    }
}

impl BlockHeightProvider for SharedBlockProvider {
    fn current_block(&self) -> u64 {
        self.block.load(Ordering::Acquire)
    }
}

// ── Schedule ──────────────────────────────────────────────────────────────

/// Price schedule that tracks the last update time and block.
#[derive(Debug)]
pub struct PriceSchedule {
    mode: UpdateMode,
    last_update_time: Instant,
    last_update_block: u64,
    /// When the schedule next wants to fire. Only meaningful for
    /// `UpdateMode::Every`. Includes jitter.
    next_fire_time: Instant,
    /// Fractional jitter, in `[0, 1]`. `0` disables jitter.
    jitter: f64,
    /// Incremented on each [`mark_updated`](Self::mark_updated); seeds
    /// the deterministic jitter for the next interval.
    jitter_counter: u64,
}

impl PriceSchedule {
    /// Create a schedule with the given mode and no jitter.
    #[must_use]
    pub fn new(mode: UpdateMode) -> Self {
        let now = Instant::now();
        Self {
            mode,
            last_update_time: now,
            last_update_block: 0,
            next_fire_time: now,
            jitter: 0.0,
            jitter_counter: 0,
        }
    }

    /// Validate the schedule.
    pub fn validate(&self) -> Result<(), UpdateModeError> {
        self.mode.validate()
    }

    /// Set the jitter fraction.
    ///
    /// `jitter` is clamped to `[0, 1]`. For `UpdateMode::Every`, the next
    /// fire time is **recomputed** to reflect the new jitter. For block
    /// modes, this is a no-op.
    ///
    /// # Semantics
    ///
    /// An interval of `d` fires between `d` and `d × (1 + jitter)` after
    /// the previous update. The jitter is additive, not symmetric.
    #[must_use]
    pub fn with_jitter(mut self, jitter: f64) -> Self {
        self.jitter = jitter.clamp(0.0, 1.0);
        if let UpdateMode::Every(base) = self.mode {
            self.next_fire_time = self.last_update_time + self.jittered(base);
        }
        self
    }

    /// Reset both the time and the block to their initial values.
    pub fn reset(&mut self) {
        let now = Instant::now();
        self.last_update_time = now;
        self.last_update_block = 0;
        self.next_fire_time = now;
        self.jitter_counter = 0;
    }

    /// Reset only the time component.
    pub fn reset_time(&mut self) {
        let now = Instant::now();
        self.last_update_time = now;
        self.next_fire_time = now;
    }

    /// Reset only the block component.
    pub fn reset_block(&mut self, block: u64) {
        self.last_update_block = block;
    }

    /// Whether an update is due.
    ///
    /// - `PerBlock`: true when `current_block != last_update_block`.
    /// - `EveryBlocks(n)`: true when `current_block - last_update_block >= n`.
    /// - `Every(d)`: true when `Instant::now() >= next_fire_time`
    ///   (jitter already folded in).
    ///
    /// For block modes, `current_block` must be `Some`. Passing `None`
    /// returns `false` — call [`run_once`](PriceUpdater::run_once) to see
    /// the misconfiguration error.
    #[must_use]
    pub fn should_update(&self, current_block: Option<u64>) -> bool {
        match self.mode {
            UpdateMode::PerBlock => {
                current_block.map_or(false, |b| b != self.last_update_block)
            }
            UpdateMode::EveryBlocks(n) => current_block
                .map_or(false, |b| b.saturating_sub(self.last_update_block) >= n),
            UpdateMode::Every(_) => Instant::now() >= self.next_fire_time,
        }
    }

    /// Time until the next time-based fire. Returns `Duration::ZERO` for
    /// block modes and when the schedule is already due.
    #[must_use]
    pub fn time_until_next(&self) -> Duration {
        match self.mode {
            UpdateMode::Every(_) => self
                .next_fire_time
                .saturating_duration_since(Instant::now()),
            _ => Duration::ZERO,
        }
    }

    /// Record that an update was performed.
    ///
    /// For `UpdateMode::Every`, recomputes the next fire time with a
    /// **new** deterministic jitter offset (counter incremented). For
    /// block modes, updates the tracked block only.
    pub fn mark_updated(&mut self, current_block: Option<u64>) {
        self.last_update_time = Instant::now();
        if let Some(b) = current_block {
            self.last_update_block = b;
        }
        if let UpdateMode::Every(base) = self.mode {
            self.jitter_counter = self.jitter_counter.wrapping_add(1);
            self.next_fire_time = self.last_update_time + self.jittered(base);
        }
    }

    /// Time since the last update.
    #[must_use]
    pub fn elapsed_since_update(&self) -> Duration {
        self.last_update_time.elapsed()
    }

    /// Current mode.
    #[must_use]
    pub fn mode(&self) -> UpdateMode {
        self.mode
    }

    /// Current jitter fraction.
    #[must_use]
    pub fn jitter(&self) -> f64 {
        self.jitter
    }

    /// Compute the jittered duration for `base` using the current
    /// counter and jitter.
    fn jittered(&self, base: Duration) -> Duration {
        // Clamp to the minimum interval so a zero-duration schedule
        // (which `validate` rejects) can never busy-loop even if the
        // caller bypasses validation.
        let base = base.max(MIN_INTERVAL);
        if self.jitter <= 0.0 {
            return base;
        }
        let base_ns = base.as_nanos().min(u64::MAX as u128) as u64;
        let jitter_ns = (base_ns as f64 * self.jitter).min(u64::MAX as f64) as u64;
        if jitter_ns == 0 {
            return base;
        }
        let offset = deterministic_offset(self.jitter_counter, base_ns) % jitter_ns;
        base + Duration::from_nanos(offset)
    }
}

/// Deterministic offset derived from `(counter, seed)` using a SplitMix64
/// finalizer. Stable across runs and platforms.
#[inline]
fn deterministic_offset(counter: u64, seed: u64) -> u64 {
    let mut z = counter
        .wrapping_add(seed)
        .wrapping_add(0x9E37_79B9_7F4A_7C15);
    z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
    z ^ (z >> 31)
}

// ── Updater ───────────────────────────────────────────────────────────────

/// Price updater that runs in the background and drives a
/// [`GasPricingManager`].
pub struct PriceUpdater {
    manager: Arc<GasPricingManager>,
    schedule: PriceSchedule,
    block_provider: Option<Box<dyn BlockHeightProvider>>,
    demand_provider: Option<Box<dyn Fn() -> ResourceUsage + Send + Sync>>,
    poll_interval: Duration,
    backoff: Duration,
}

impl PriceUpdater {
    /// Create a new updater.
    ///
    /// # Errors
    ///
    /// Returns `Err` if `schedule.validate()` fails (e.g. `Every(Duration::ZERO)`).
    pub fn new(
        manager: Arc<GasPricingManager>,
        schedule: PriceSchedule,
    ) -> Result<Self, UpdateError> {
        schedule.validate()?;
        Ok(Self {
            manager,
            schedule,
            block_provider: None,
            demand_provider: None,
            poll_interval: DEFAULT_POLL_INTERVAL,
            backoff: DEFAULT_BACKOFF,
        })
    }

    /// Set a block height provider. Required for `PerBlock` and
    /// `EveryBlocks` modes.
    #[must_use]
    pub fn with_block_provider(mut self, provider: impl BlockHeightProvider + 'static) -> Self {
        self.block_provider = Some(Box::new(provider));
        self
    }

    /// Set the demand provider that returns current resource usage.
    ///
    /// When unset, a documented placeholder demand is used. Production
    /// callers should always supply one.
    #[must_use]
    pub fn with_demand_provider<F>(mut self, provider: F) -> Self
    where
        F: Fn() -> ResourceUsage + Send + Sync + 'static,
    {
        self.demand_provider = Some(Box::new(provider));
        self
    }

    /// Override the poll interval used by block-based modes.
    ///
    /// Defaults to [`DEFAULT_POLL_INTERVAL`].
    #[must_use]
    pub fn with_poll_interval(mut self, interval: Duration) -> Self {
        self.poll_interval = interval.max(MIN_INTERVAL);
        self
    }

    /// Override the backoff applied after a failed adjustment.
    ///
    /// Defaults to [`DEFAULT_BACKOFF`].
    #[must_use]
    pub fn with_backoff(mut self, backoff: Duration) -> Self {
        self.backoff = backoff;
        self
    }

    /// Snapshot of the schedule.
    #[must_use]
    pub fn schedule(&self) -> &PriceSchedule {
        &self.schedule
    }

    /// Run a single update cycle.
    ///
    /// # Behavior
    ///
    /// - `Ok(Applied)` — the schedule was due and the adjustment succeeded.
    /// - `Ok(NotDue)` — the schedule was not due; nothing happened.
    /// - `Err(MissingBlockProvider)` — block mode without a provider.
    /// - `Err(AdjustFailed(_))` — the manager rejected the adjustment
    ///   after retrying.
    ///
    /// A failure leaves the schedule **unmarked**, so the next poll
    /// retries the adjustment.
    pub async fn run_once(&mut self) -> Result<UpdateOutcome, UpdateError> {
        let current_block = match self.schedule.mode {
            UpdateMode::PerBlock | UpdateMode::EveryBlocks(_) => {
                let p = self
                    .block_provider
                    .as_ref()
                    .ok_or(UpdateError::MissingBlockProvider)?;
                Some(p.current_block())
            }
            UpdateMode::Every(_) => None,
        };

        if !self.schedule.should_update(current_block) {
            trace!("price schedule not due");
            return Ok(UpdateOutcome::NotDue);
        }

        let demand = self.fetch_demand();
        debug!(?demand, "running scheduled price adjustment");

        // Non-blocking: `adjust_async` yields during backoff instead of
        // sleeping on the tokio worker thread.
        self.manager
            .adjust_async(&demand)
            .await
            .map_err(UpdateError::AdjustFailed)?;

        self.schedule.mark_updated(current_block);
        info!("scheduled price adjustment applied");
        Ok(UpdateOutcome::Applied)
    }

    fn fetch_demand(&self) -> ResourceUsage {
        match &self.demand_provider {
            Some(f) => f(),
            None => {
                // Documented placeholder. Callers running in production
                // should always supply a `demand_provider`.
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
            }
        }
    }

    /// Run the background updater loop until cancelled.
    ///
    /// # Errors
    ///
    /// Returns immediately (via `Err` in the returned future) if the
    /// schedule requires a block provider and none was set. Transient
    /// adjustment failures are logged and retried with `backoff`; they
    /// do not terminate the loop.
    pub async fn run_loop(mut self, cancellation_token: CancellationToken) -> Result<(), UpdateError> {
        if self.schedule.mode.requires_block_provider() && self.block_provider.is_none() {
            return Err(UpdateError::MissingBlockProvider);
        }

        info!(
            mode = ?self.schedule.mode,
            jitter = self.schedule.jitter,
            "starting price updater loop"
        );

        loop {
            // Sleep for the correct amount: exact for time modes, poll
            // interval for block modes.
            let sleep_duration = match self.schedule.mode {
                UpdateMode::Every(_) => self.schedule.time_until_next().max(MIN_INTERVAL),
                UpdateMode::PerBlock | UpdateMode::EveryBlocks(_) => self.poll_interval,
            };

            tokio::select! {
                _ = sleep(sleep_duration) => {
                    match self.run_once().await {
                        Ok(UpdateOutcome::Applied) => {}
                        Ok(UpdateOutcome::NotDue) => {}
                        Err(e) => {
                            warn!(error = %e, "price adjustment failed; backing off");
                            tokio::select! {
                                _ = sleep(self.backoff) => {}
                                _ = cancellation_token.cancelled() => {
                                    info!("price updater loop cancelled during backoff");
                                    return Ok(());
                                }
                            }
                        }
                    }
                }
                _ = cancellation_token.cancelled() => {
                    info!("price updater loop cancelled");
                    return Ok(());
                }
            }
        }
    }
}

// ── Convenience spawner ───────────────────────────────────────────────────

/// Spawn a [`PriceUpdater`] on the tokio runtime.
///
/// The spawned task's `JoinHandle` completes with the value of
/// [`PriceUpdater::run_loop`]. Callers that only need fire-and-forget
/// behaviour can drop the handle; the task stops when `cancellation_token`
/// is cancelled.
///
/// # Errors
///
/// Returns `Err` if the schedule is invalid or the mode requires a block
/// provider that has not been set.
///
/// # Panics
///
/// Panics if called outside a tokio runtime (`tokio::spawn` requirement).
pub fn spawn_updater(
    manager: Arc<GasPricingManager>,
    schedule: PriceSchedule,
    cancellation_token: CancellationToken,
) -> Result<tokio::task::JoinHandle<Result<(), UpdateError>>, UpdateError> {
    let updater = PriceUpdater::new(manager, schedule)?;
    Ok(tokio::spawn(updater.run_loop(cancellation_token)))
}

// ── Tests ─────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::gas::GasPricingConfig;

    fn test_manager() -> Arc<GasPricingManager> {
        let cfg = GasPricingConfig {
            enable_adaptive: false, // scheduling is tested here, not the manager's own updater
            enable_metrics: false,
            ..Default::default()
        };
        Arc::new(GasPricingManager::new(cfg).unwrap())
    }

    // ── UpdateMode::validate ────────────────────────────────────────────

    #[test]
    fn mode_validate_accepts_valid_modes() {
        assert_eq!(UpdateMode::PerBlock.validate(), Ok(()));
        assert_eq!(UpdateMode::EveryBlocks(5).validate(), Ok(()));
        assert_eq!(
            UpdateMode::Every(Duration::from_secs(1)).validate(),
            Ok(())
        );
    }

    #[test]
    fn mode_validate_rejects_zero_block_count() {
        assert_eq!(
            UpdateMode::EveryBlocks(0).validate(),
            Err(UpdateModeError::ZeroBlockCount)
        );
    }

    #[test]
    fn mode_validate_rejects_zero_duration() {
        assert_eq!(
            UpdateMode::Every(Duration::ZERO).validate(),
            Err(UpdateModeError::ZeroDuration)
        );
    }

    #[test]
    fn requires_block_provider() {
        assert!(UpdateMode::PerBlock.requires_block_provider());
        assert!(UpdateMode::EveryBlocks(3).requires_block_provider());
        assert!(!UpdateMode::Every(Duration::from_secs(1)).requires_block_provider());
    }

    // ── PerBlock / EveryBlocks ──────────────────────────────────────────

    #[test]
    fn per_block_fires_only_on_block_change() {
        let mut s = PriceSchedule::new(UpdateMode::PerBlock);
        assert!(s.should_update(Some(10)));
        s.mark_updated(Some(10));
        assert!(!s.should_update(Some(10)));
        assert!(s.should_update(Some(11)));
    }

    #[test]
    fn every_blocks_fires_after_n_blocks() {
        let mut s = PriceSchedule::new(UpdateMode::EveryBlocks(3));
        s.mark_updated(Some(5));
        assert!(!s.should_update(Some(6)));
        assert!(!s.should_update(Some(7)));
        assert!(s.should_update(Some(8)));
    }

    #[test]
    fn block_modes_without_provider_never_fire() {
        // `should_update` is defensive: a block mode without a current
        // block returns `false`. The actual error is raised in
        // `run_once`.
        let s = PriceSchedule::new(UpdateMode::PerBlock);
        assert!(!s.should_update(None));
    }

    #[test]
    fn every_blocks_does_not_overflow_on_huge_n() {
        // `EveryBlocks(u64::MAX)` used to multiply by 5 and overflow.
        let mut s = PriceSchedule::new(UpdateMode::EveryBlocks(u64::MAX));
        s.mark_updated(Some(0));
        assert!(!s.should_update(Some(1)));
        assert!(s.should_update(Some(u64::MAX)));
    }

    // ── Time-based ──────────────────────────────────────────────────────

    #[test]
    fn time_schedule_fires_after_interval() {
        let mut s = PriceSchedule::new(UpdateMode::Every(Duration::from_millis(50)));
        s.mark_updated(None);
        assert!(!s.should_update(None));
        std::thread::sleep(Duration::from_millis(80));
        assert!(s.should_update(None));
    }

    #[test]
    fn time_until_next_counts_down() {
        let mut s = PriceSchedule::new(UpdateMode::Every(Duration::from_millis(200)));
        s.mark_updated(None);
        let a = s.time_until_next();
        std::thread::sleep(Duration::from_millis(50));
        let b = s.time_until_next();
        assert!(b < a);
    }

    // ── Jitter ──────────────────────────────────────────────────────────

    #[test]
    fn jitter_is_deterministic_within_an_interval() {
        // Regression: the previous implementation re-rolled the RNG on
        // every `should_update` call, so two back-to-back calls returned
        // different answers and `run_loop` could busy-loop.
        let mut s = PriceSchedule::new(UpdateMode::Every(Duration::from_millis(100)))
            .with_jitter(0.5);
        s.mark_updated(None);
        let a = s.should_update(None);
        let b = s.should_update(None);
        let c = s.should_update(None);
        assert_eq!(a, b);
        assert_eq!(b, c);
    }

    #[test]
    fn jitter_changes_across_intervals() {
        let mut s = PriceSchedule::new(UpdateMode::Every(Duration::from_millis(100)))
            .with_jitter(0.5);
        s.mark_updated(None);
        let t1 = s.time_until_next();
        s.mark_updated(None);
        let t2 = s.time_until_next();
        // Two consecutive intervals should (very likely) differ, but we
        // can't assert strict inequality — the deterministic offset could
        // collide. Assert both are in the valid band instead.
        let min = Duration::from_millis(100);
        let max = Duration::from_millis(150);
        assert!((min..=max).contains(&t1));
        assert!((min..=max).contains(&t2));
    }

    #[test]
    fn jitter_never_shortens_the_interval() {
        let mut s = PriceSchedule::new(UpdateMode::Every(Duration::from_millis(100)))
            .with_jitter(0.5);
        for _ in 0..20 {
            s.mark_updated(None);
            let d = s.time_until_next();
            assert!(d >= Duration::from_millis(100));
            assert!(d <= Duration::from_millis(150));
        }
    }

    #[test]
    fn zero_duration_is_clamped_to_min_interval() {
        // Even if the caller bypasses `validate`, the jittered duration
        // is clamped. No busy-loop.
        let mut s = PriceSchedule::new(UpdateMode::Every(Duration::ZERO));
        s.mark_updated(None);
        assert!(s.time_until_next() >= MIN_INTERVAL);
    }

    // ── Updater lifecycle ───────────────────────────────────────────────

    #[test]
    fn updater_rejects_invalid_schedule() {
        let mgr = test_manager();
        let schedule = PriceSchedule::new(UpdateMode::Every(Duration::ZERO));
        assert!(matches!(
            PriceUpdater::new(mgr, schedule),
            Err(UpdateError::InvalidMode(UpdateModeError::ZeroDuration))
        ));
    }

    #[tokio::test]
    async fn updater_run_once_applies_on_per_block() {
        let mgr = test_manager();
        let schedule = PriceSchedule::new(UpdateMode::PerBlock);
        let mut updater = PriceUpdater::new(mgr.clone(), schedule)
            .unwrap()
            .with_block_provider(FixedBlockProvider::new(1));

        assert_eq!(
            updater.run_once().await.unwrap(),
            UpdateOutcome::Applied
        );
        // Same block: not due.
        assert_eq!(updater.run_once().await.unwrap(), UpdateOutcome::NotDue);
    }

    #[tokio::test]
    async fn updater_run_once_returns_not_due_immediately_after_mark() {
        let mgr = test_manager();
        let mut schedule = PriceSchedule::new(UpdateMode::Every(Duration::from_secs(60)));
        schedule.mark_updated(None);
        let mut updater = PriceUpdater::new(mgr, schedule).unwrap();

        assert_eq!(updater.run_once().await.unwrap(), UpdateOutcome::NotDue);
    }

    #[tokio::test]
    async fn updater_run_once_missing_block_provider() {
        let mgr = test_manager();
        let schedule = PriceSchedule::new(UpdateMode::PerBlock);
        let mut updater = PriceUpdater::new(mgr, schedule).unwrap();
        let err = updater.run_once().await.unwrap_err();
        assert!(matches!(err, UpdateError::MissingBlockProvider));
    }

    #[tokio::test]
    async fn updater_run_once_advances_block_via_shared_provider() {
        let mgr = test_manager();
        let provider = SharedBlockProvider::new(0);
        let handle = provider.clone_handle();

        let schedule = PriceSchedule::new(UpdateMode::EveryBlocks(2));
        let mut updater = PriceUpdater::new(mgr, schedule)
            .unwrap()
            .with_block_provider(provider);

        // Block 0 → 1: not due.
        handle.set(1);
        assert_eq!(updater.run_once().await.unwrap(), UpdateOutcome::NotDue);

        // Block 1 → 2: due (diff = 2).
        handle.set(2);
        assert_eq!(
            updater.run_once().await.unwrap(),
            UpdateOutcome::Applied
        );
    }

    #[tokio::test]
    async fn updater_run_loop_rejects_missing_provider() {
        let mgr = test_manager();
        let schedule = PriceSchedule::new(UpdateMode::PerBlock);
        let updater = PriceUpdater::new(mgr, schedule).unwrap();
        let token = CancellationToken::new();
        let result = updater.run_loop(token).await;
        assert!(matches!(result, Err(UpdateError::MissingBlockProvider)));
    }

    #[tokio::test]
    async fn updater_run_loop_cancels_cleanly() {
        let mgr = test_manager();
        let schedule = PriceSchedule::new(UpdateMode::Every(Duration::from_secs(60)));
        let updater = PriceUpdater::new(mgr, schedule).unwrap();
        let token = CancellationToken::new();

        let handle = tokio::spawn(updater.run_loop(token.clone()));
        tokio::time::sleep(Duration::from_millis(30)).await;
        token.cancel();
        assert!(handle.await.unwrap().is_ok());
    }

    #[tokio::test]
    async fn spawn_updater_propagates_config_errors() {
        let mgr = test_manager();
        let schedule = PriceSchedule::new(UpdateMode::Every(Duration::ZERO));
        let token = CancellationToken::new();
        assert!(matches!(
            spawn_updater(mgr, schedule, token),
            Err(UpdateError::InvalidMode(_))
        ));
    }

    // ── Providers ───────────────────────────────────────────────────────

    #[test]
    fn fixed_provider_updates() {
        let mut p = FixedBlockProvider::new(100);
        assert_eq!(p.current_block(), 100);
        p.set_block(200);
        assert_eq!(p.current_block(), 200);
    }

    #[test]
    fn shared_provider_is_observable_via_clone() {
        let a = SharedBlockProvider::new(0);
        let b = a.clone_handle();
        a.set(42);
        assert_eq!(b.current_block(), 42);
        b.set(7);
        assert_eq!(a.current_block(), 7);
    }

    // ── Helpers ─────────────────────────────────────────────────────────

    #[test]
    fn deterministic_offset_is_stable() {
        let x = deterministic_offset(1, 100);
        let y = deterministic_offset(1, 100);
        assert_eq!(x, y);
    }

    #[test]
    fn deterministic_offset_changes_with_counter() {
        // Extremely unlikely to collide; assert at least one difference
        // over a small range.
        let base = deterministic_offset(0, 100);
        let mut differs = false;
        for c in 1..10 {
            if deterministic_offset(c, 100) != base {
                differs = true;
                break;
            }
        }
        assert!(differs);
    }
}
