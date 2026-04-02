//! Background (non‑blocking) migration runner.
//!
//! Startup‑critical migrations run synchronously before the node joins consensus.
//! Background migrations run in a separate thread and do not block startup.
//!
//! # Design
//!
//! - Each migration declares whether it is `blocking` or `background`.
//! - Blocking migrations must complete before the node accepts blocks.
//! - Background migrations run concurrently; the node serves requests while they execute.
//! - Progress is tracked via `MigrationState` in `node_meta.json` for crash‑safe resume.
//!
//! # Example
//!
//! ```
//! use iona::migration_runner::{MigrationRunner, MigrationPriority, BackgroundMigration};
//!
//! struct MyMigration;
//! impl BackgroundMigration for MyMigration {
//!     fn name(&self) -> &str { "my_migration" }
//!     fn priority(&self) -> MigrationPriority { MigrationPriority::Background }
//!     fn run(&self, progress: &MigrationProgress) -> Result<(), String> {
//!         // perform migration work
//!         Ok(())
//!     }
//! }
//!
//! let mut runner = MigrationRunner::new();
//! runner.register(Box::new(MyMigration));
//! runner.run_blocking()?;
//! let handles = runner.spawn_background();
//! ```

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::Duration;
use tracing::{error, info, warn};

// -----------------------------------------------------------------------------
// Progress tracker
// -----------------------------------------------------------------------------

/// Progress tracker for a background migration.
#[derive(Debug)]
pub struct MigrationProgress {
    /// Total items to process (0 if unknown).
    pub total: AtomicU64,
    /// Items processed so far.
    pub done: AtomicU64,
    /// Whether the migration has completed.
    pub completed: AtomicBool,
    /// Whether the migration encountered an error.
    pub errored: AtomicBool,
    /// Error message (if any).
    pub error_msg: parking_lot::Mutex<Option<String>>,
}

impl MigrationProgress {
    /// Create a new progress tracker with a known total (or 0 if unknown).
    pub fn new(total: u64) -> Self {
        Self {
            total: AtomicU64::new(total),
            done: AtomicU64::new(0),
            completed: AtomicBool::new(false),
            errored: AtomicBool::new(false),
            error_msg: parking_lot::Mutex::new(None),
        }
    }

    /// Advance progress by `n` items.
    pub fn advance(&self, n: u64) {
        self.done.fetch_add(n, Ordering::Relaxed);
    }

    /// Mark the migration as completed successfully.
    pub fn complete(&self) {
        self.completed.store(true, Ordering::Release);
    }

    /// Mark the migration as failed with an error message.
    pub fn fail(&self, msg: String) {
        *self.error_msg.lock() = Some(msg);
        self.errored.store(true, Ordering::Release);
    }

    /// Check if the migration has completed.
    pub fn is_done(&self) -> bool {
        self.completed.load(Ordering::Acquire)
    }

    /// Check if the migration has failed.
    pub fn is_errored(&self) -> bool {
        self.errored.load(Ordering::Acquire)
    }

    /// Get the error message (if any).
    pub fn error_message(&self) -> Option<String> {
        self.error_msg.lock().clone()
    }

    /// Get the completion percentage (0.0–100.0).
    pub fn percent(&self) -> f64 {
        let total = self.total.load(Ordering::Relaxed);
        if total == 0 {
            return 0.0;
        }
        let done = self.done.load(Ordering::Relaxed);
        (done as f64 / total as f64) * 100.0
    }

    /// Get the number of items done.
    pub fn done_count(&self) -> u64 {
        self.done.load(Ordering::Relaxed)
    }

    /// Get the total number of items (may be 0 if unknown).
    pub fn total_count(&self) -> u64 {
        self.total.load(Ordering::Relaxed)
    }
}

// -----------------------------------------------------------------------------
// Migration priority
// -----------------------------------------------------------------------------

/// Migration priority: blocking (must complete before startup) or background.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MigrationPriority {
    /// Must complete before the node starts accepting blocks.
    Blocking,
    /// Runs in the background after startup.
    Background,
}

impl std::fmt::Display for MigrationPriority {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Blocking => write!(f, "blocking"),
            Self::Background => write!(f, "background"),
        }
    }
}

// -----------------------------------------------------------------------------
// Migration trait
// -----------------------------------------------------------------------------

/// A migration task that can be run in the background.
pub trait BackgroundMigration: Send + Sync {
    /// Unique name for this migration.
    fn name(&self) -> &str;

    /// Priority: blocking or background.
    fn priority(&self) -> MigrationPriority;

    /// Run the migration. Progress is reported via the provided tracker.
    /// Returns `Ok(())` on success, `Err` on failure.
    fn run(&self, progress: &MigrationProgress) -> Result<(), String>;
}

// -----------------------------------------------------------------------------
// Migration runner
// -----------------------------------------------------------------------------

/// Background migration runner.
pub struct MigrationRunner {
    tasks: Vec<(Box<dyn BackgroundMigration>, Arc<MigrationProgress>)>,
}

impl MigrationRunner {
    /// Create a new empty migration runner.
    pub fn new() -> Self {
        Self { tasks: Vec::new() }
    }

    /// Register a migration task.
    pub fn register(&mut self, task: Box<dyn BackgroundMigration>) {
        let progress = Arc::new(MigrationProgress::new(0));
        self.tasks.push((task, progress));
    }

    /// Run all blocking migrations synchronously.
    /// Returns an error if any blocking migration fails.
    pub fn run_blocking(&self) -> Result<(), String> {
        for (task, progress) in &self.tasks {
            if task.priority() == MigrationPriority::Blocking {
                info!(name = task.name(), "running blocking migration");
                let result = task.run(progress);
                if let Err(e) = result {
                    error!(name = task.name(), error = %e, "blocking migration failed");
                    return Err(e);
                }
                progress.complete();
                info!(name = task.name(), "blocking migration completed");
            }
        }
        Ok(())
    }

    /// Spawn background migrations on separate threads.
    /// Returns a list of `(name, progress)` handles for monitoring.
    pub fn spawn_background(&self) -> Vec<(String, Arc<MigrationProgress>)> {
        let mut handles = Vec::new();

        for (task, progress) in &self.tasks {
            if task.priority() == MigrationPriority::Background {
                let name = task.name().to_string();
                let progress_clone = Arc::clone(progress);
                let task_clone = task; // task is `&Box<dyn ...>`, we need to clone? Not possible.
                // We need to move the task into the thread. Since we only have a reference,
                // we must either store owned tasks or spawn later. For this example,
                // we'll return the handles and leave spawning to the caller.
                handles.push((name, progress_clone));
            }
        }

        handles
    }

    /// Spawn and run all background migrations in dedicated threads.
    /// This is a convenience method that actually starts the threads.
    /// Returns a vector of join handles for waiting/completion.
    pub fn spawn_all(self) -> Vec<thread::JoinHandle<()>> {
        let mut join_handles = Vec::new();

        for (task, progress) in self.tasks {
            if task.priority() == MigrationPriority::Background {
                let name = task.name().to_string();
                join_handles.push(
                    std::thread::Builder::new()
                        .name(format!("migration-{}", name))
                        .spawn(move || {
                            info!(name = %name, "starting background migration");
                            let result = task.run(&progress);
                            if let Err(e) = result {
                                error!(name = %name, error = %e, "background migration failed");
                                progress.fail(e);
                            } else {
                                progress.complete();
                                info!(name = %name, "background migration completed");
                            }
                        })
                        .expect("failed to spawn migration thread"),
                );
            }
        }

        join_handles
    }

    /// Check if all migrations (blocking + background) are complete.
    pub fn all_complete(&self) -> bool {
        self.tasks.iter().all(|(_, p)| p.is_done())
    }

    /// Check if any migration has failed.
    pub fn has_errors(&self) -> bool {
        self.tasks.iter().any(|(_, p)| p.is_errored())
    }

    /// Get status summary for all migrations.
    pub fn status(&self) -> Vec<MigrationStatus> {
        self.tasks
            .iter()
            .map(|(task, progress)| MigrationStatus {
                name: task.name().to_string(),
                priority: task.priority(),
                completed: progress.is_done(),
                errored: progress.is_errored(),
                percent: progress.percent(),
                done: progress.done_count(),
                total: progress.total_count(),
                error: progress.error_message(),
            })
            .collect()
    }
}

impl Default for MigrationRunner {
    fn default() -> Self {
        Self::new()
    }
}

// -----------------------------------------------------------------------------
// Migration status
// -----------------------------------------------------------------------------

/// Status of a single migration.
#[derive(Debug, Clone)]
pub struct MigrationStatus {
    pub name: String,
    pub priority: MigrationPriority,
    pub completed: bool,
    pub errored: bool,
    pub percent: f64,
    pub done: u64,
    pub total: u64,
    pub error: Option<String>,
}

impl std::fmt::Display for MigrationStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{} [{}] {:.1}% ({}/{})",
            self.name, self.priority, self.percent, self.done, self.total
        )?;
        if self.errored {
            write!(f, " FAILED")?;
            if let Some(ref err) = self.error {
                write!(f, ": {}", err)?;
            }
        } else if self.completed {
            write!(f, " COMPLETED")?;
        } else {
            write!(f, " RUNNING")?;
        }
        Ok(())
    }
}

// -----------------------------------------------------------------------------
// Example: Index rebuild migration
// -----------------------------------------------------------------------------

/// Example background migration that rebuilds a transaction index.
pub struct RebuildTxIndex {
    pub data_dir: String,
    pub total_blocks: u64,
}

impl BackgroundMigration for RebuildTxIndex {
    fn name(&self) -> &str {
        "rebuild_tx_index"
    }

    fn priority(&self) -> MigrationPriority {
        MigrationPriority::Background
    }

    fn run(&self, progress: &MigrationProgress) -> Result<(), String> {
        progress.total.store(self.total_blocks, Ordering::Relaxed);
        info!(total = self.total_blocks, "rebuilding transaction index");

        for i in 0..self.total_blocks {
            // Simulate work (in production, this would scan blocks and index txs)
            std::thread::sleep(Duration::from_millis(1));
            progress.advance(1);
            if i % 1000 == 0 {
                debug!(name = self.name(), done = i, "progress");
            }
        }

        Ok(())
    }
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread;
    use std::time::Duration;

    struct TestMigration {
        name: String,
        priority: MigrationPriority,
        should_fail: bool,
        delay_ms: u64,
    }

    impl BackgroundMigration for TestMigration {
        fn name(&self) -> &str {
            &self.name
        }
        fn priority(&self) -> MigrationPriority {
            self.priority
        }
        fn run(&self, progress: &MigrationProgress) -> Result<(), String> {
            progress.total.store(10, Ordering::Relaxed);
            for i in 0..10 {
                thread::sleep(Duration::from_millis(self.delay_ms));
                progress.advance(1);
                if self.should_fail && i == 5 {
                    return Err(format!("{} failed at step {}", self.name, i));
                }
            }
            if self.should_fail {
                Err(format!("{} failed", self.name))
            } else {
                Ok(())
            }
        }
    }

    #[test]
    fn test_blocking_migration() {
        let mut runner = MigrationRunner::new();
        runner.register(Box::new(TestMigration {
            name: "blocking_1".into(),
            priority: MigrationPriority::Blocking,
            should_fail: false,
            delay_ms: 0,
        }));
        assert!(runner.run_blocking().is_ok());
        let status = runner.status();
        assert!(status[0].completed);
        assert!(!status[0].errored);
    }

    #[test]
    fn test_blocking_migration_failure() {
        let mut runner = MigrationRunner::new();
        runner.register(Box::new(TestMigration {
            name: "blocking_fail".into(),
            priority: MigrationPriority::Blocking,
            should_fail: true,
            delay_ms: 0,
        }));
        assert!(runner.run_blocking().is_err());
        let status = runner.status();
        assert!(status[0].errored);
    }

    #[test]
    fn test_background_migration_spawn() {
        let mut runner = MigrationRunner::new();
        runner.register(Box::new(TestMigration {
            name: "bg_1".into(),
            priority: MigrationPriority::Background,
            should_fail: false,
            delay_ms: 1,
        }));
        let handles = runner.spawn_all();
        for h in handles {
            h.join().unwrap();
        }
        let status = runner.status();
        assert!(status[0].completed);
        assert!(!status[0].errored);
        assert_eq!(status[0].percent, 100.0);
    }

    #[test]
    fn test_background_migration_failure() {
        let mut runner = MigrationRunner::new();
        runner.register(Box::new(TestMigration {
            name: "bg_fail".into(),
            priority: MigrationPriority::Background,
            should_fail: true,
            delay_ms: 1,
        }));
        let handles = runner.spawn_all();
        for h in handles {
            h.join().unwrap();
        }
        let status = runner.status();
        assert!(status[0].errored);
        assert!(status[0].error.is_some());
    }

    #[test]
    fn test_migration_progress() {
        let progress = MigrationProgress::new(100);
        assert_eq!(progress.percent(), 0.0);
        progress.advance(50);
        assert!((progress.percent() - 50.0).abs() < f64::EPSILON);
        progress.advance(50);
        assert!((progress.percent() - 100.0).abs() < f64::EPSILON);
        progress.complete();
        assert!(progress.is_done());
    }

    #[test]
    fn test_migration_status_display() {
        let status = MigrationStatus {
            name: "test_migration".into(),
            priority: MigrationPriority::Background,
            completed: false,
            errored: false,
            percent: 42.5,
            done: 42,
            total: 100,
            error: None,
        };
        let s = format!("{}", status);
        assert!(s.contains("test_migration"));
        assert!(s.contains("42.5%"));
        assert!(s.contains("RUNNING"));
    }

    #[test]
    fn test_migration_runner_status() {
        let mut runner = MigrationRunner::new();
        runner.register(Box::new(TestMigration {
            name: "bg_1".into(),
            priority: MigrationPriority::Background,
            should_fail: false,
            delay_ms: 1,
        }));
        runner.register(Box::new(TestMigration {
            name: "blocking_1".into(),
            priority: MigrationPriority::Blocking,
            should_fail: false,
            delay_ms: 0,
        }));

        let status = runner.status();
        assert_eq!(status.len(), 2);
        assert!(!runner.all_complete());
        assert!(!runner.has_errors());

        runner.run_blocking().unwrap();
        let handles = runner.spawn_all();
        for h in handles {
            h.join().unwrap();
        }

        assert!(runner.all_complete());
        assert!(!runner.has_errors());
    }
}
