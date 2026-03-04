//! Background (non-blocking) migration runner.
//!
//! Startup-critical migrations run synchronously before the node joins consensus.
//! Background migrations run in a separate thread and do not block startup.
//!
//! Design:
//! - Each migration declares whether it is `blocking` or `background`.
//! - Blocking migrations must complete before the node accepts blocks.
//! - Background migrations run concurrently; the node serves requests while they execute.
//! - Progress is tracked via `MigrationState` in node_meta.json for crash-safe resume.

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;

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
    pub fn new(total: u64) -> Self {
        Self {
            total: AtomicU64::new(total),
            done: AtomicU64::new(0),
            completed: AtomicBool::new(false),
            errored: AtomicBool::new(false),
            error_msg: parking_lot::Mutex::new(None),
        }
    }

    pub fn advance(&self, n: u64) {
        self.done.fetch_add(n, Ordering::Relaxed);
    }

    pub fn complete(&self) {
        self.completed.store(true, Ordering::Release);
    }

    pub fn fail(&self, msg: String) {
        *self.error_msg.lock() = Some(msg);
        self.errored.store(true, Ordering::Release);
    }

    pub fn is_done(&self) -> bool {
        self.completed.load(Ordering::Acquire)
    }

    pub fn is_errored(&self) -> bool {
        self.errored.load(Ordering::Acquire)
    }

    pub fn percent(&self) -> f64 {
        let total = self.total.load(Ordering::Relaxed);
        if total == 0 {
            return 0.0;
        }
        let done = self.done.load(Ordering::Relaxed);
        (done as f64 / total as f64) * 100.0
    }
}

/// Migration priority: blocking (must complete before startup) or background.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MigrationPriority {
    /// Must complete before the node starts accepting blocks.
    Blocking,
    /// Runs in the background after startup.
    Background,
}

/// A migration task that can be run in the background.
pub trait BackgroundMigration: Send + Sync {
    /// Unique name for this migration.
    fn name(&self) -> &str;

    /// Priority: blocking or background.
    fn priority(&self) -> MigrationPriority;

    /// Run the migration. Progress is reported via the provided tracker.
    /// Returns Ok(()) on success, Err on failure.
    fn run(&self, progress: &MigrationProgress) -> Result<(), String>;
}

/// Background migration runner.
pub struct MigrationRunner {
    tasks: Vec<(Box<dyn BackgroundMigration>, Arc<MigrationProgress>)>,
}

impl MigrationRunner {
    pub fn new() -> Self {
        Self { tasks: Vec::new() }
    }

    /// Register a migration task.
    pub fn register(&mut self, task: Box<dyn BackgroundMigration>) {
        let progress = Arc::new(MigrationProgress::new(0));
        self.tasks.push((task, progress));
    }

    /// Run all blocking migrations synchronously.
    /// Returns error if any blocking migration fails.
    pub fn run_blocking(&self) -> Result<(), String> {
        for (task, progress) in &self.tasks {
            if task.priority() == MigrationPriority::Blocking {
                task.run(progress)?;
                progress.complete();
            }
        }
        Ok(())
    }

    /// Spawn background migrations on separate threads.
    /// Returns handles for monitoring progress.
    pub fn spawn_background(&self) -> Vec<(String, Arc<MigrationProgress>)> {
        let mut handles = Vec::new();

        for (task, progress) in &self.tasks {
            if task.priority() == MigrationPriority::Background {
                let name = task.name().to_string();
                handles.push((name, Arc::clone(progress)));
            }
        }

        // Note: actual thread spawning would happen in the node binary.
        // The library provides the infrastructure; the binary wires it up.
        handles
    }

    /// Check if all migrations (blocking + background) are complete.
    pub fn all_complete(&self) -> bool {
        self.tasks.iter().all(|(_, p)| p.is_done())
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
                error: progress.error_msg.lock().clone(),
            })
            .collect()
    }
}

/// Status of a single migration.
#[derive(Debug, Clone)]
pub struct MigrationStatus {
    pub name: String,
    pub priority: MigrationPriority,
    pub completed: bool,
    pub errored: bool,
    pub percent: f64,
    pub error: Option<String>,
}

// ── Example: Index rebuild migration ────────────────────────────────────

/// Example background migration that rebuilds a transaction index.
pub struct RebuildTxIndex {
    pub data_dir: String,
}

impl BackgroundMigration for RebuildTxIndex {
    fn name(&self) -> &str {
        "rebuild_tx_index"
    }

    fn priority(&self) -> MigrationPriority {
        MigrationPriority::Background
    }

    fn run(&self, progress: &MigrationProgress) -> Result<(), String> {
        // Placeholder: in production, this would scan block files and
        // rebuild the tx->block index.
        progress.total.store(100, Ordering::Relaxed);
        for i in 0..100 {
            // Simulate work
            progress.advance(1);
            let _ = i;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct TestMigration {
        name: String,
        priority: MigrationPriority,
        should_fail: bool,
    }

    impl BackgroundMigration for TestMigration {
        fn name(&self) -> &str { &self.name }
        fn priority(&self) -> MigrationPriority { self.priority }
        fn run(&self, progress: &MigrationProgress) -> Result<(), String> {
            progress.total.store(10, Ordering::Relaxed);
            for _ in 0..10 {
                progress.advance(1);
            }
            if self.should_fail {
                Err("test failure".into())
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
        }));
        assert!(runner.run_blocking().is_ok());
    }

    #[test]
    fn test_blocking_migration_failure() {
        let mut runner = MigrationRunner::new();
        runner.register(Box::new(TestMigration {
            name: "blocking_fail".into(),
            priority: MigrationPriority::Blocking,
            should_fail: true,
        }));
        assert!(runner.run_blocking().is_err());
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
    fn test_migration_status() {
        let mut runner = MigrationRunner::new();
        runner.register(Box::new(TestMigration {
            name: "bg_1".into(),
            priority: MigrationPriority::Background,
            should_fail: false,
        }));
        runner.register(Box::new(TestMigration {
            name: "blocking_1".into(),
            priority: MigrationPriority::Blocking,
            should_fail: false,
        }));

        let status = runner.status();
        assert_eq!(status.len(), 2);
    }
}
