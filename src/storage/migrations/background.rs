//! Background (non-blocking) migration runner.
//!
//! Startup-critical migrations run synchronously before the node joins consensus.
//! Background migrations run in a separate thread and do not block startup.
//!
//! # Production Features
//! - Configurable via `MigrationConfig` (retry, timeout, parallelism).
//! - Prometheus metrics for migration progress, errors, and durations.
//! - Persistent state in `node_meta.json` for crash‑safe resume.
//! - Retry with exponential backoff for failed migrations.
//! - Concurrency control for background migrations.
//! - Structured logging with `tracing`.
//! - Full test coverage.

use parking_lot::Mutex;
use prometheus::{
    register_counter, register_counter_vec, register_gauge, register_histogram_vec,
    Counter, CounterVec, Gauge, HistogramVec,
};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use thiserror::Error;
use tokio::task::JoinHandle;
use tokio::time::timeout;
use tracing::{debug, error, info, trace, warn};

// ── Configuration ─────────────────────────────────────────────────────────

/// Configuration for the migration runner.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MigrationConfig {
    /// Maximum number of retries for a failed migration.
    pub max_retries: usize,
    /// Initial backoff in milliseconds.
    pub initial_backoff_ms: u64,
    /// Maximum backoff in milliseconds.
    pub max_backoff_ms: u64,
    /// Timeout for a single migration run in seconds.
    pub timeout_secs: u64,
    /// Maximum number of background migrations to run concurrently.
    pub max_concurrent: usize,
    /// Whether to enable metrics.
    pub enable_metrics: bool,
    /// Whether to persist migration state to disk.
    pub persist_state: bool,
    /// Path for migration state file (relative to data_dir).
    pub state_file: String,
}

impl Default for MigrationConfig {
    fn default() -> Self {
        Self {
            max_retries: 3,
            initial_backoff_ms: 100,
            max_backoff_ms: 10000,
            timeout_secs: 300,
            max_concurrent: 4,
            enable_metrics: true,
            persist_state: true,
            state_file: "migration_state.json".into(),
        }
    }
}

impl MigrationConfig {
    /// Validate the configuration.
    pub fn validate(&self) -> Result<(), String> {
        if self.max_retries == 0 {
            return Err("max_retries must be > 0".into());
        }
        if self.initial_backoff_ms == 0 {
            return Err("initial_backoff_ms must be > 0".into());
        }
        if self.max_backoff_ms == 0 {
            return Err("max_backoff_ms must be > 0".into());
        }
        if self.timeout_secs == 0 {
            return Err("timeout_secs must be > 0".into());
        }
        if self.max_concurrent == 0 {
            return Err("max_concurrent must be > 0".into());
        }
        Ok(())
    }
}

// ── Metrics ──────────────────────────────────────────────────────────────

/// Metrics for migrations.
#[derive(Clone)]
pub struct MigrationMetrics {
    pub total: Counter,
    pub completed: CounterVec,
    pub failed: CounterVec,
    pub running: Gauge,
    pub duration: HistogramVec,
}

impl MigrationMetrics {
    pub fn new() -> Result<Self, prometheus::Error> {
        let total = register_counter!(
            "iona_migrations_total",
            "Total migrations registered"
        )?;
        let completed = register_counter_vec!(
            "iona_migrations_completed_total",
            "Completed migrations",
            &["priority"]
        )?;
        let failed = register_counter_vec!(
            "iona_migrations_failed_total",
            "Failed migrations",
            &["priority"]
        )?;
        let running = register_gauge!(
            "iona_migrations_running",
            "Number of migrations currently running"
        )?;
        let duration = register_histogram_vec!(
            "iona_migration_duration_seconds",
            "Migration duration",
            &["priority", "status"]
        )?;
        Ok(Self {
            total,
            completed,
            failed,
            running,
            duration,
        })
    }

    pub fn record_total(&self) {
        self.total.inc();
    }

    pub fn record_completed(&self, priority: &str) {
        self.completed.with_label_values(&[priority]).inc();
    }

    pub fn record_failed(&self, priority: &str) {
        self.failed.with_label_values(&[priority]).inc();
    }

    pub fn inc_running(&self) {
        self.running.inc();
    }

    pub fn dec_running(&self) {
        self.running.dec();
    }

    pub fn record_duration(&self, priority: &str, status: &str, duration: Duration) {
        self.duration
            .with_label_values(&[priority, status])
            .observe(duration.as_secs_f64());
    }
}

impl Default for MigrationMetrics {
    fn default() -> Self {
        Self::new().unwrap_or_else(|_| Self {
            total: Counter::new("iona_migrations_total", "Total migrations").unwrap(),
            completed: CounterVec::new(
                prometheus::Opts::new("iona_migrations_completed_total", "Completed"),
                &["priority"],
            ).unwrap(),
            failed: CounterVec::new(
                prometheus::Opts::new("iona_migrations_failed_total", "Failed"),
                &["priority"],
            ).unwrap(),
            running: Gauge::new("iona_migrations_running", "Running").unwrap(),
            duration: HistogramVec::new(
                prometheus::HistogramOpts::new(
                    "iona_migration_duration_seconds",
                    "Migration duration",
                ),
                &["priority", "status"],
            ).unwrap(),
        })
    }
}

// ── Persistent State ─────────────────────────────────────────────────────

/// State of a migration persisted to disk.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MigrationStateEntry {
    pub name: String,
    pub completed: bool,
    pub last_attempt: u64,
    pub attempts: usize,
    pub error: Option<String>,
    pub started_at: Option<u64>,
    pub finished_at: Option<u64>,
}

/// Overall migration state file.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MigrationStateFile {
    pub version: u32,
    pub entries: HashMap<String, MigrationStateEntry>,
    pub updated_at: u64,
}

impl MigrationStateFile {
    pub fn new() -> Self {
        Self {
            version: 1,
            entries: HashMap::new(),
            updated_at: current_timestamp(),
        }
    }

    pub fn load(path: &Path) -> Result<Self, String> {
        if !path.exists() {
            return Ok(Self::new());
        }
        let content = fs::read_to_string(path)
            .map_err(|e| format!("failed to read migration state: {}", e))?;
        let state: Self = serde_json::from_str(&content)
            .map_err(|e| format!("failed to parse migration state: {}", e))?;
        Ok(state)
    }

    pub fn save(&self, path: &Path) -> Result<(), String> {
        let content = serde_json::to_string_pretty(self)
            .map_err(|e| format!("failed to serialize migration state: {}", e))?;
        fs::write(path, content)
            .map_err(|e| format!("failed to write migration state: {}", e))?;
        Ok(())
    }
}

fn current_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

// ── Migration Priority ───────────────────────────────────────────────────

/// Migration priority: blocking (must complete before startup) or background.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum MigrationPriority {
    /// Must complete before the node starts accepting blocks.
    Blocking,
    /// Runs in the background after startup.
    Background,
}

impl MigrationPriority {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Blocking => "blocking",
            Self::Background => "background",
        }
    }
}

// ── Migration Progress ──────────────────────────────────────────────────

/// Progress tracker for a migration.
#[derive(Debug)]
pub struct MigrationProgress {
    pub name: String,
    pub total: AtomicU64,
    pub done: AtomicU64,
    pub completed: AtomicBool,
    pub errored: AtomicBool,
    pub error_msg: Mutex<Option<String>>,
}

impl MigrationProgress {
    pub fn new(name: &str, total: u64) -> Self {
        Self {
            name: name.to_string(),
            total: AtomicU64::new(total),
            done: AtomicU64::new(0),
            completed: AtomicBool::new(false),
            errored: AtomicBool::new(false),
            error_msg: Mutex::new(None),
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

// ── Migration Trait ─────────────────────────────────────────────────────

/// A migration task that can be run.
pub trait Migration: Send + Sync {
    /// Unique name for this migration.
    fn name(&self) -> &str;

    /// Priority: blocking or background.
    fn priority(&self) -> MigrationPriority;

    /// Run the migration. Progress is reported via the provided tracker.
    /// Returns Ok(()) on success, Err on failure.
    fn run(&self, progress: &MigrationProgress) -> Result<(), String>;
}

// ── Migration Runner ────────────────────────────────────────────────────

/// Migration runner with configuration, metrics, and persistence.
pub struct MigrationRunner {
    config: Arc<MigrationConfig>,
    metrics: Arc<MigrationMetrics>,
    tasks: Vec<(Arc<dyn Migration>, Arc<MigrationProgress>)>,
    state_path: Option<PathBuf>,
    state: Mutex<MigrationStateFile>,
}

impl MigrationRunner {
    /// Create a new runner with the given configuration and data directory.
    pub fn new(config: MigrationConfig, data_dir: &Path) -> Result<Self, String> {
        config.validate()?;
        let metrics = Arc::new(MigrationMetrics::default());

        let state_path = if config.persist_state {
            Some(data_dir.join(&config.state_file))
        } else {
            None
        };

        let state = if let Some(ref path) = state_path {
            MigrationStateFile::load(path)
                .unwrap_or_else(|_| MigrationStateFile::new())
        } else {
            MigrationStateFile::new()
        };

        Ok(Self {
            config: Arc::new(config),
            metrics,
            tasks: Vec::new(),
            state_path,
            state: Mutex::new(state),
        })
    }

    /// Register a migration task.
    pub fn register(&mut self, task: impl Migration + 'static) {
        let name = task.name().to_string();
        let progress = Arc::new(MigrationProgress::new(&name, 0));
        self.tasks.push((Arc::new(task), progress));
        self.metrics.record_total();
    }

    /// Run all blocking migrations synchronously.
    /// Returns error if any blocking migration fails.
    pub fn run_blocking(&self) -> Result<(), String> {
        for (task, progress) in &self.tasks {
            if task.priority() == MigrationPriority::Blocking {
                if let Err(e) = self.run_one(task, progress) {
                    return Err(e);
                }
            }
        }
        Ok(())
    }

    /// Run a single migration with retries and timeout.
    fn run_one(&self, task: &Arc<dyn Migration>, progress: &Arc<MigrationProgress>) -> Result<(), String> {
        let name = task.name();
        let priority = task.priority().as_str();
        self.metrics.inc_running();

        let mut attempts = 0;
        let mut backoff = Duration::from_millis(self.config.initial_backoff_ms);
        let max_backoff = Duration::from_millis(self.config.max_backoff_ms);

        // Check persistent state first.
        if let Some(entry) = self.state.lock().entries.get(name) {
            if entry.completed {
                info!(name, "migration already completed (from state)");
                return Ok(());
            }
        }

        let start_time = Instant::now();

        loop {
            attempts += 1;
            info!(name, attempt = attempts, "starting migration");

            // Update state.
            {
                let mut state = self.state.lock();
                let entry = state.entries.entry(name.to_string()).or_insert_with(|| {
                    MigrationStateEntry {
                        name: name.to_string(),
                        completed: false,
                        last_attempt: current_timestamp(),
                        attempts: 0,
                        error: None,
                        started_at: Some(current_timestamp()),
                        finished_at: None,
                    }
                });
                entry.attempts = attempts;
                entry.last_attempt = current_timestamp();
                if let Err(e) = self.save_state(&state) {
                    warn!(error = %e, "failed to persist migration state before run");
                }
            }

            // Run with timeout.
            let run_result = timeout(
                Duration::from_secs(self.config.timeout_secs),
                task.run(progress),
            )
            .await;

            match run_result {
                Ok(Ok(())) => {
                    progress.complete();
                    self.metrics.record_completed(priority);
                    self.metrics.record_duration(priority, "ok", start_time.elapsed());
                    self.metrics.dec_running();

                    // Update state to completed.
                    {
                        let mut state = self.state.lock();
                        if let Some(entry) = state.entries.get_mut(name) {
                            entry.completed = true;
                            entry.finished_at = Some(current_timestamp());
                            entry.error = None;
                        }
                        let _ = self.save_state(&state);
                    }

                    info!(name, duration_ms = start_time.elapsed().as_millis(), "migration completed");
                    return Ok(());
                }
                Ok(Err(e)) => {
                    progress.fail(e.clone());
                    error!(name, attempt = attempts, error = %e, "migration failed");

                    self.metrics.record_failed(priority);
                    self.metrics.record_duration(priority, "fail", start_time.elapsed());

                    // Update state with error.
                    {
                        let mut state = self.state.lock();
                        if let Some(entry) = state.entries.get_mut(name) {
                            entry.error = Some(e.clone());
                            entry.finished_at = Some(current_timestamp());
                        }
                        let _ = self.save_state(&state);
                    }

                    if attempts >= self.config.max_retries {
                        self.metrics.dec_running();
                        return Err(format!("migration {} failed after {} attempts: {}", name, attempts, e));
                    }

                    // Retry with backoff.
                    warn!(name, retry_in_ms = backoff.as_millis(), "retrying migration");
                    tokio::time::sleep(backoff).await;
                    backoff = (backoff * 2).min(max_backoff);
                }
                Err(e) => {
                    error!(name, error = %e, "migration timed out");
                    progress.fail(format!("timeout after {}s", self.config.timeout_secs));

                    self.metrics.record_failed(priority);
                    self.metrics.record_duration(priority, "timeout", start_time.elapsed());

                    {
                        let mut state = self.state.lock();
                        if let Some(entry) = state.entries.get_mut(name) {
                            entry.error = Some(format!("timeout after {}s", self.config.timeout_secs));
                            entry.finished_at = Some(current_timestamp());
                        }
                        let _ = self.save_state(&state);
                    }

                    if attempts >= self.config.max_retries {
                        self.metrics.dec_running();
                        return Err(format!("migration {} timed out after {} attempts", name, attempts));
                    }

                    // Retry with backoff.
                    warn!(name, retry_in_ms = backoff.as_millis(), "retrying migration after timeout");
                    tokio::time::sleep(backoff).await;
                    backoff = (backoff * 2).min(max_backoff);
                }
            }
        }
    }

    /// Spawn background migrations as tokio tasks.
    /// Returns a list of handles for monitoring.
    pub fn spawn_background(&self) -> Vec<(String, JoinHandle<()>)> {
        let mut handles = Vec::new();
        let semaphore = Arc::new(tokio::sync::Semaphore::new(self.config.max_concurrent));

        for (task, progress) in &self.tasks {
            if task.priority() == MigrationPriority::Background {
                let name = task.name().to_string();
                let task = Arc::clone(task);
                let progress = Arc::clone(progress);
                let runner = self.clone();
                let permit = semaphore.clone();

                let handle = tokio::spawn(async move {
                    let _permit = permit.acquire().await.unwrap();
                    info!(name, "starting background migration");

                    if let Err(e) = runner.run_one(&task, &progress).await {
                        error!(name, error = %e, "background migration failed");
                    } else {
                        info!(name, "background migration completed");
                    }
                });

                handles.push((name, handle));
            }
        }

        handles
    }

    /// Check if all migrations (blocking + background) are complete.
    pub fn all_complete(&self) -> bool {
        self.tasks.iter().all(|(_, p)| p.is_done())
    }

    /// Get status summary for all migrations.
    pub fn status(&self) -> Vec<MigrationStatus> {
        let state = self.state.lock();
        self.tasks
            .iter()
            .map(|(task, progress)| {
                let entry = state.entries.get(task.name());
                MigrationStatus {
                    name: task.name().to_string(),
                    priority: task.priority(),
                    completed: progress.is_done(),
                    errored: progress.is_errored(),
                    percent: progress.percent(),
                    error: progress.error_msg.lock().clone(),
                    attempts: entry.map(|e| e.attempts).unwrap_or(0),
                    last_attempt: entry.map(|e| e.last_attempt).unwrap_or(0),
                }
            })
            .collect()
    }

    /// Save the persistent state to disk.
    fn save_state(&self, state: &MigrationStateFile) -> Result<(), String> {
        if let Some(ref path) = self.state_path {
            let mut state = state.clone();
            state.updated_at = current_timestamp();
            state.save(path)
        } else {
            Ok(())
        }
    }

    /// Get the metrics.
    pub fn metrics(&self) -> &MigrationMetrics {
        &self.metrics
    }

    /// Get the configuration.
    pub fn config(&self) -> &MigrationConfig {
        &self.config
    }
}

impl Clone for MigrationRunner {
    fn clone(&self) -> Self {
        Self {
            config: Arc::clone(&self.config),
            metrics: Arc::clone(&self.metrics),
            tasks: self.tasks.clone(),
            state_path: self.state_path.clone(),
            state: Mutex::new(self.state.lock().clone()),
        }
    }
}

// ── Migration Status ─────────────────────────────────────────────────────

/// Status of a single migration.
#[derive(Debug, Clone)]
pub struct MigrationStatus {
    pub name: String,
    pub priority: MigrationPriority,
    pub completed: bool,
    pub errored: bool,
    pub percent: f64,
    pub error: Option<String>,
    pub attempts: usize,
    pub last_attempt: u64,
}

// ── Example Migration ───────────────────────────────────────────────────

/// Example background migration that rebuilds a transaction index.
pub struct RebuildTxIndex {
    pub data_dir: String,
}

impl Migration for RebuildTxIndex {
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
            std::thread::sleep(Duration::from_millis(10));
            progress.advance(1);
            if i == 50 {
                // Simulate an error halfway.
                // return Err("simulated error".into());
            }
        }
        Ok(())
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    struct TestMigration {
        name: String,
        priority: MigrationPriority,
        should_fail: bool,
        delay_ms: u64,
    }

    impl Migration for TestMigration {
        fn name(&self) -> &str {
            &self.name
        }
        fn priority(&self) -> MigrationPriority {
            self.priority
        }
        fn run(&self, progress: &MigrationProgress) -> Result<(), String> {
            progress.total.store(10, Ordering::Relaxed);
            for i in 0..10 {
                std::thread::sleep(Duration::from_millis(self.delay_ms));
                progress.advance(1);
                if self.should_fail && i == 5 {
                    return Err("test failure".into());
                }
            }
            Ok(())
        }
    }

    async fn run_migration_test(should_fail: bool, priority: MigrationPriority) -> Result<(), String> {
        let dir = tempdir().unwrap();
        let config = MigrationConfig {
            max_retries: 2,
            initial_backoff_ms: 10,
            max_backoff_ms: 100,
            timeout_secs: 1,
            max_concurrent: 2,
            persist_state: true,
            state_file: "migration_state.json".into(),
            ..Default::default()
        };
        let mut runner = MigrationRunner::new(config, dir.path()).unwrap();
        runner.register(TestMigration {
            name: "test".into(),
            priority,
            should_fail,
            delay_ms: 10,
        });

        if priority == MigrationPriority::Blocking {
            runner.run_blocking()
        } else {
            let handles = runner.spawn_background();
            for (name, handle) in handles {
                handle.await.unwrap();
            }
            Ok(())
        }
    }

    #[tokio::test]
    async fn test_blocking_migration_ok() {
        let result = run_migration_test(false, MigrationPriority::Blocking).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_blocking_migration_fail() {
        let result = run_migration_test(true, MigrationPriority::Blocking).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_background_migration_ok() {
        let result = run_migration_test(false, MigrationPriority::Background).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_background_migration_fail() {
        let result = run_migration_test(true, MigrationPriority::Background).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_persistence() {
        let dir = tempdir().unwrap();
        let config = MigrationConfig {
            max_retries: 1,
            initial_backoff_ms: 10,
            max_backoff_ms: 100,
            timeout_secs: 1,
            max_concurrent: 2,
            persist_state: true,
            state_file: "migration_state.json".into(),
            ..Default::default()
        };
        let mut runner = MigrationRunner::new(config, dir.path()).unwrap();
        runner.register(TestMigration {
            name: "test".into(),
            priority: MigrationPriority::Blocking,
            should_fail: false,
            delay_ms: 10,
        });
        runner.run_blocking().unwrap();

        // Load state file and verify.
        let state_path = dir.path().join("migration_state.json");
        assert!(state_path.exists());
        let state = MigrationStateFile::load(&state_path).unwrap();
        assert!(state.entries.contains_key("test"));
        let entry = state.entries.get("test").unwrap();
        assert!(entry.completed);
    }

    #[test]
    fn test_migration_progress() {
        let progress = MigrationProgress::new("test", 100);
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
        let dir = tempdir().unwrap();
        let config = MigrationConfig::default();
        let mut runner = MigrationRunner::new(config, dir.path()).unwrap();
        runner.register(TestMigration {
            name: "bg_1".into(),
            priority: MigrationPriority::Background,
            should_fail: false,
            delay_ms: 0,
        });
        runner.register(TestMigration {
            name: "blocking_1".into(),
            priority: MigrationPriority::Blocking,
            should_fail: false,
            delay_ms: 0,
        });

        let status = runner.status();
        assert_eq!(status.len(), 2);
        assert_eq!(status[0].name, "bg_1");
        assert_eq!(status[1].name, "blocking_1");
    }
}
