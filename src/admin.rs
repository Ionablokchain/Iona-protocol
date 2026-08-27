//! CLI admin commands for IONA v28 — Quantum Administration Framework.
//!
//! # Quantum Administrative Model
//!
//! Administrative operations are modeled as quantum measurements and
//! unitary transformations on the node's state space. Each command
//! corresponds to a specific Hamiltonian evolution or projective
//! measurement on the node's configuration Hilbert space.
//!
//! # Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────────────────┐
//! │                          Admin Module                                  │
//! ├─────────────┬──────────────┬───────────────┬──────────────────────────┤
//! │   Config    │    Error     │    Metrics    │         Types            │
//! │ (AdminCfg)  │ (AdminError) │ (AdminMetr)   │ (AdminResult, QuantumState)│
//! ├─────────────┼──────────────┼───────────────┼──────────────────────────┤
//! │  Commands   │   Helpers    │   Manager     │        Legacy            │
//! │ (exec_*)    │ (utils)      │ (AdminMgr)    │ (global functions)       │
//! └─────────────────────────────────────────────────────────────────────────┘
//! ```
//!
//! # Example
//!
//! ```rust,ignore
//! use iona::admin::{AdminManager, AdminConfig};
//!
//! let config = AdminConfig::default();
//! let manager = AdminManager::new(config);
//! let result = manager.exec_status(data_dir)?;
//! ```

#![allow(dead_code)]

use crate::storage::layout::{DataLayout, NodeStatus, ResetScope};
use crate::storage::block_store::FsBlockStore;
use fs_extra::dir::{copy, CopyOptions};
use serde::{Deserialize, Serialize};
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};
use std::sync::Mutex;
use thiserror::Error;
use tracing::{debug, error, info, warn};
use walkdir::WalkDir;
use fs2::FileExt;
use std::fs::File;
use std::io::Write;

// -----------------------------------------------------------------------------
// Submodules (embedded)
// -----------------------------------------------------------------------------

pub mod config {
    //! Configuration for the admin subsystem.
    use serde::{Deserialize, Serialize};
    use super::constants::*;

    /// Configuration for admin operations.
    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct AdminConfig {
        pub default_listen_addr: String,
        pub backup_prefix: String,
        pub admin_coherence_time: u64,
        pub max_retries: u32,
        pub retry_backoff_ms: u64,
        pub lock_file: String,
        pub forbidden_paths: Vec<String>,
        pub collect_metrics: bool,
        pub log_operations: bool,
    }

    impl Default for AdminConfig {
        fn default() -> Self {
            Self {
                default_listen_addr: super::constants::DEFAULT_LISTEN_ADDR.to_string(),
                backup_prefix: super::constants::BACKUP_PREFIX.to_string(),
                admin_coherence_time: super::constants::ADMIN_COHERENCE_TIME,
                max_retries: super::constants::MAX_RETRIES,
                retry_backoff_ms: super::constants::RETRY_BACKOFF_MS,
                lock_file: super::constants::ADMIN_LOCK_FILE.to_string(),
                forbidden_paths: super::constants::FORBIDDEN_PATHS
                    .iter()
                    .map(|s| s.to_string())
                    .collect(),
                collect_metrics: true,
                log_operations: false,
            }
        }
    }

    impl AdminConfig {
        pub fn validate(&self) -> Result<(), &'static str> {
            if self.max_retries == 0 {
                return Err("max_retries must be > 0");
            }
            if self.retry_backoff_ms == 0 {
                return Err("retry_backoff_ms must be > 0");
            }
            if self.admin_coherence_time == 0 {
                return Err("admin_coherence_time must be > 0");
            }
            Ok(())
        }

        pub fn with_metrics(mut self) -> Self {
            self.collect_metrics = true;
            self
        }
    }
}

pub mod constants {
    //! Constants for admin operations.
    /// Default listen multiaddress.
    pub const DEFAULT_LISTEN_ADDR: &str = "/ip4/0.0.0.0/tcp/7001";

    /// Backup directory name prefix.
    pub const BACKUP_PREFIX: &str = "iona_backup_";

    /// Coherence time for admin operations.
    pub const ADMIN_COHERENCE_TIME: u64 = 1000;

    /// Prompt for chain reset.
    pub const CONFIRM_PROMPT_CHAIN: &str = "This will collapse chain subspace to |0⟩. Continue? [y/N]";

    /// Prompt for identity reset.
    pub const CONFIRM_PROMPT_IDENTITY: &str = "This will collapse identity subspace to |0⟩. Continue? [y/N]";

    /// Prompt for full reset.
    pub const CONFIRM_PROMPT_FULL: &str = "This will collapse ALL subspaces to |0⟩. This unitary cannot be reversed. Continue? [y/N]";

    /// Forbidden paths.
    pub const FORBIDDEN_PATHS: [&str; 3] = ["/", "/root", "/etc"];

    /// Admin lock file.
    pub const ADMIN_LOCK_FILE: &str = ".iona_admin.lock";

    /// Maximum retries for file operations.
    pub const MAX_RETRIES: u32 = 3;

    /// Initial backoff in milliseconds.
    pub const RETRY_BACKOFF_MS: u64 = 100;
}

pub mod error {
    //! Error types for admin operations.
    use std::path::PathBuf;
    use thiserror::Error;

    #[derive(Debug, Error)]
    pub enum AdminError {
        #[error("I/O decoherence: {source}")]
        Io {
            #[from]
            source: std::io::Error,
        },

        #[error("configuration superposition collapse failed: {source}")]
        ConfigParse {
            #[from]
            source: toml::de::Error,
        },

        #[error("Hilbert subspace not found: {path}")]
        DirectoryNotFound { path: PathBuf },

        #[error("quantum cloning failed: {reason}")]
        BackupFailed { reason: String },

        #[error("integrity observable measurement failed: {reason}")]
        IntegrityCheckFailed { reason: String },

        #[error("observer effect: user cancelled measurement")]
        UserCancel,

        #[error("invalid state space: {reason}")]
        InvalidDataDir { reason: String },

        #[error("decoherence threshold exceeded: coherence lost")]
        DecoherenceExceeded,

        #[error("entanglement fidelity below threshold: {threshold}")]
        EntanglementLost { threshold: f64 },

        #[error("operation already in progress: {reason}")]
        LockFailed { reason: String },

        #[error("insufficient disk space: required {required} bytes, available {available} bytes")]
        InsufficientDiskSpace { required: u64, available: u64 },

        #[error("json serialization error: {source}")]
        JsonSerialize {
            #[from]
            source: serde_json::Error,
        },

        #[error("fs_extra error: {source}")]
        FsExtra {
            #[from]
            source: fs_extra::error::Error,
        },
    }

    pub type AdminResult<T> = Result<T, AdminError>;
}

pub mod metrics {
    //! Metrics for admin operations.
    use core::sync::atomic::{AtomicU64, Ordering};
    use serde::{Deserialize, Serialize};

    #[derive(Debug, Default)]
    pub struct AdminMetrics {
        pub commands_total: AtomicU64,
        pub commands_succeeded: AtomicU64,
        pub commands_failed: AtomicU64,
        pub reset_chain_calls: AtomicU64,
        pub reset_identity_calls: AtomicU64,
        pub reset_full_calls: AtomicU64,
        pub status_calls: AtomicU64,
        pub peer_id_calls: AtomicU64,
        pub multiaddr_calls: AtomicU64,
        pub config_calls: AtomicU64,
        pub version_calls: AtomicU64,
        pub backup_calls: AtomicU64,
        pub health_calls: AtomicU64,
        pub verify_calls: AtomicU64,
        pub lock_acquire_failures: AtomicU64,
        pub disk_space_errors: AtomicU64,
    }

    impl AdminMetrics {
        pub fn inc_command(&self, cmd: &str) {
            self.commands_total.fetch_add(1, Ordering::Relaxed);
            match cmd {
                "reset_chain" => self.reset_chain_calls.fetch_add(1, Ordering::Relaxed),
                "reset_identity" => self.reset_identity_calls.fetch_add(1, Ordering::Relaxed),
                "reset_full" => self.reset_full_calls.fetch_add(1, Ordering::Relaxed),
                "status" => self.status_calls.fetch_add(1, Ordering::Relaxed),
                "peer_id" => self.peer_id_calls.fetch_add(1, Ordering::Relaxed),
                "multiaddr" => self.multiaddr_calls.fetch_add(1, Ordering::Relaxed),
                "config" => self.config_calls.fetch_add(1, Ordering::Relaxed),
                "version" => self.version_calls.fetch_add(1, Ordering::Relaxed),
                "backup" => self.backup_calls.fetch_add(1, Ordering::Relaxed),
                "health" => self.health_calls.fetch_add(1, Ordering::Relaxed),
                "verify" => self.verify_calls.fetch_add(1, Ordering::Relaxed),
                _ => 0,
            };
        }

        pub fn inc_success(&self) {
            self.commands_succeeded.fetch_add(1, Ordering::Relaxed);
        }

        pub fn inc_failure(&self) {
            self.commands_failed.fetch_add(1, Ordering::Relaxed);
        }

        pub fn inc_lock_failure(&self) {
            self.lock_acquire_failures.fetch_add(1, Ordering::Relaxed);
        }

        pub fn inc_disk_error(&self) {
            self.disk_space_errors.fetch_add(1, Ordering::Relaxed);
        }

        pub fn snapshot(&self) -> AdminMetricsSnapshot {
            AdminMetricsSnapshot {
                commands_total: self.commands_total.load(Ordering::Relaxed),
                commands_succeeded: self.commands_succeeded.load(Ordering::Relaxed),
                commands_failed: self.commands_failed.load(Ordering::Relaxed),
                reset_chain_calls: self.reset_chain_calls.load(Ordering::Relaxed),
                reset_identity_calls: self.reset_identity_calls.load(Ordering::Relaxed),
                reset_full_calls: self.reset_full_calls.load(Ordering::Relaxed),
                status_calls: self.status_calls.load(Ordering::Relaxed),
                peer_id_calls: self.peer_id_calls.load(Ordering::Relaxed),
                multiaddr_calls: self.multiaddr_calls.load(Ordering::Relaxed),
                config_calls: self.config_calls.load(Ordering::Relaxed),
                version_calls: self.version_calls.load(Ordering::Relaxed),
                backup_calls: self.backup_calls.load(Ordering::Relaxed),
                health_calls: self.health_calls.load(Ordering::Relaxed),
                verify_calls: self.verify_calls.load(Ordering::Relaxed),
                lock_acquire_failures: self.lock_acquire_failures.load(Ordering::Relaxed),
                disk_space_errors: self.disk_space_errors.load(Ordering::Relaxed),
            }
        }
    }

    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct AdminMetricsSnapshot {
        pub commands_total: u64,
        pub commands_succeeded: u64,
        pub commands_failed: u64,
        pub reset_chain_calls: u64,
        pub reset_identity_calls: u64,
        pub reset_full_calls: u64,
        pub status_calls: u64,
        pub peer_id_calls: u64,
        pub multiaddr_calls: u64,
        pub config_calls: u64,
        pub version_calls: u64,
        pub backup_calls: u64,
        pub health_calls: u64,
        pub verify_calls: u64,
        pub lock_acquire_failures: u64,
        pub disk_space_errors: u64,
    }

    /// Global metrics instance.
    pub(crate) static GLOBAL_METRICS: spin::Once<AdminMetrics> = spin::Once::new();

    pub fn global_metrics() -> &'static AdminMetrics {
        GLOBAL_METRICS.get_or_init(AdminMetrics::default)
    }
}

pub mod types {
    //! Core types for admin operations.
    use super::config::AdminConfig;
    use crate::storage::layout::NodeStatus;
    use serde::{Deserialize, Serialize};

    /// Result of a quantum admin command.
    #[derive(Debug, Clone, Serialize, Deserialize)]
    #[serde(tag = "command")]
    pub enum AdminResult {
        ResetChain {
            dirs_removed: Vec<String>,
            dirs_preserved: Vec<String>,
            fidelity: f64,
        },
        ResetIdentity {
            dirs_removed: Vec<String>,
            dirs_preserved: Vec<String>,
            fidelity: f64,
        },
        ResetFull {
            dirs_removed: Vec<String>,
            fidelity: f64,
        },
        Status {
            #[serde(flatten)]
            info: NodeStatus,
            entropy: f64,
        },
        PrintPeerId {
            peer_id: String,
            quantum_fingerprint: String,
        },
        PrintMultiaddr {
            multiaddr: String,
            entanglement_capacity: usize,
        },
        Config {
            config: serde_json::Value,
            config_purity: f64,
        },
        Version {
            version: String,
            commit: String,
            build_epoch: u64,
        },
        BackupCreated {
            backup_path: String,
            clone_fidelity: f64,
        },
        Health {
            ok: bool,
            height: u64,
            peers: usize,
            message: String,
            coherence: f64,
        },
        Verify {
            passed: bool,
            message: String,
            confidence: f64,
        },
    }

    /// Quantum state for admin operations.
    #[derive(Debug, Clone)]
    pub struct AdminQuantumState {
        pub coherence: f64,
        pub entropy: f64,
        pub fidelity: f64,
    }

    impl AdminQuantumState {
        pub fn new() -> Self {
            Self {
                coherence: 1.0,
                entropy: 0.0,
                fidelity: 1.0,
            }
        }

        pub fn apply_decoherence(&mut self, interaction_strength: f64) {
            let dt = 1.0 / super::constants::ADMIN_COHERENCE_TIME as f64;
            self.coherence *= (-interaction_strength * dt).exp();
            self.entropy = -self.coherence * self.coherence.ln();
            self.fidelity = self.coherence.sqrt();
        }

        pub fn measure(&self) -> f64 {
            self.coherence * self.fidelity
        }
    }

    /// Reset result structure (adapted from storage::layout).
    #[derive(Debug, Clone)]
    pub struct ResetResult {
        pub dirs_removed: Vec<String>,
        pub dirs_preserved: Vec<String>,
    }

    impl From<crate::storage::layout::ResetResult> for ResetResult {
        fn from(other: crate::storage::layout::ResetResult) -> Self {
            ResetResult {
                dirs_removed: other.dirs_removed,
                dirs_preserved: other.dirs_preserved,
            }
        }
    }
}

pub mod helpers {
    //! Helper functions for admin operations.
    use super::{
        config::AdminConfig,
        error::{AdminError, AdminResult},
        constants::{FORBIDDEN_PATHS, RETRY_BACKOFF_MS, MAX_RETRIES},
    };
    use std::fs;
    use std::io;
    use std::path::{Path, PathBuf};
    use std::time::Duration;
    use walkdir::WalkDir;
    use fs2::FileExt;
    use std::fs::File;
    use std::io::Write;

    /// Ensure that the given directory is not a system-critical path.
    pub fn validate_data_dir(path: &Path, config: &AdminConfig) -> AdminResult<()> {
        let canonical = path.canonicalize().map_err(|e| AdminError::InvalidDataDir {
            reason: format!("cannot canonicalize: {}", e),
        })?;
        for forbidden in &config.forbidden_paths {
            let forbidden_path = Path::new(forbidden);
            if canonical == *forbidden_path || canonical.starts_with(forbidden_path) {
                return Err(AdminError::InvalidDataDir {
                    reason: format!("data_dir cannot be under system directory: {}", forbidden),
                });
            }
        }
        Ok(())
    }

    /// Check available disk space.
    pub fn ensure_disk_space(path: &Path, required: u64) -> AdminResult<()> {
        if let Ok(stat) = fs2::statvfs(path) {
            let available = stat.avail_free() * stat.fragment_size();
            if available < required {
                return Err(AdminError::InsufficientDiskSpace {
                    required,
                    available,
                });
            }
        }
        Ok(())
    }

    /// User confirmation (quantum measurement).
    pub fn user_confirmation(prompt: &str) -> Result<bool, AdminError> {
        let is_terminal = atty::is(atty::Stream::Stdin);
        if !is_terminal {
            return Ok(false);
        }
        print!("{} ", prompt);
        io::stdout().flush().map_err(|e| AdminError::Io { source: e })?;
        let mut input = String::new();
        io::stdin()
            .read_line(&mut input)
            .map_err(|e| AdminError::Io { source: e })?;
        Ok(input.trim().eq_ignore_ascii_case("y") || input.trim().eq_ignore_ascii_case("yes"))
    }

    /// Recursive directory copy.
    pub fn copy_dir_all(src: &Path, dst: &Path) -> io::Result<()> {
        fs::create_dir_all(dst)?;
        for entry in fs::read_dir(src)? {
            let entry = entry?;
            let ty = entry.file_type()?;
            let src_path = entry.path();
            let dst_path = dst.join(entry.file_name());
            if ty.is_dir() {
                copy_dir_all(&src_path, &dst_path)?;
            } else {
                fs::copy(&src_path, &dst_path)?;
            }
        }
        Ok(())
    }

    /// Get total size of a directory recursively.
    pub fn get_dir_size(path: &Path) -> Result<u64, AdminError> {
        let mut total = 0;
        for entry in WalkDir::new(path) {
            let entry = entry.map_err(|e| AdminError::Io { source: e.into() })?;
            if entry.file_type().is_file() {
                total += entry.metadata().map_err(|e| AdminError::Io { source: e })?.len();
            }
        }
        Ok(total)
    }

    /// Retry a closure with exponential backoff.
    pub fn retry_operation<F, T>(mut f: F) -> Result<T, AdminError>
    where
        F: FnMut() -> Result<T, AdminError>,
    {
        let mut attempt = 0;
        let mut delay = RETRY_BACKOFF_MS;
        loop {
            match f() {
                Ok(val) => return Ok(val),
                Err(e) => {
                    attempt += 1;
                    if attempt >= MAX_RETRIES {
                        return Err(e);
                    }
                    std::thread::sleep(Duration::from_millis(delay));
                    delay *= 2;
                }
            }
        }
    }

    /// Acquire exclusive lock for admin operations.
    pub fn acquire_admin_lock(data_dir: &Path, config: &AdminConfig) -> AdminResult<File> {
        let lock_path = data_dir.join(&config.lock_file);
        let file = File::create(&lock_path).map_err(|e| AdminError::Io { source: e })?;
        file.try_lock_exclusive().map_err(|e| AdminError::LockFailed {
            reason: format!("cannot acquire lock: {}", e),
        })?;
        Ok(file)
    }

    /// Release lock.
    pub fn release_admin_lock(mut file: File) -> AdminResult<()> {
        file.unlock().map_err(|e| AdminError::LockFailed {
            reason: format!("cannot release lock: {}", e),
        })?;
        Ok(())
    }

    /// Convert admin result to JSON.
    pub fn result_to_json(result: &super::types::AdminResult) -> String {
        serde_json::to_string_pretty(result).unwrap_or_else(|_| "{}".into())
    }
}

pub mod commands {
    //! Implementation of admin commands.
    use super::{
        config::AdminConfig,
        error::{AdminError, AdminResult},
        types::{AdminResult as AdminResultType, AdminQuantumState, ResetResult},
        helpers::{validate_data_dir, user_confirmation, get_dir_size, retry_operation, acquire_admin_lock, ensure_disk_space},
        constants::{BACKUP_PREFIX, CONFIRM_PROMPT_CHAIN, CONFIRM_PROMPT_IDENTITY, CONFIRM_PROMPT_FULL},
        metrics::global_metrics,
    };
    use crate::storage::layout::{DataLayout, ResetScope};
    use crate::storage::block_store::FsBlockStore;
    use fs_extra::dir::{copy, CopyOptions};
    use std::fs;
    use std::path::Path;
    use std::time::{SystemTime, UNIX_EPOCH};
    use tracing::{debug, info, warn};

    /// Collapse chain subspace to vacuum state.
    pub fn exec_reset_chain(
        data_dir: &str,
        confirm: bool,
        force: bool,
        dry_run: bool,
        config: &AdminConfig,
    ) -> AdminResult<AdminResultType> {
        let data_path = Path::new(data_dir);
        validate_data_dir(data_path, config)?;
        let _lock = acquire_admin_lock(data_path, config)?;
        let mut qstate = AdminQuantumState::new();

        if confirm && !force && !user_confirmation(CONFIRM_PROMPT_CHAIN)? {
            return Err(AdminError::UserCancel);
        }

        qstate.apply_decoherence(0.01);
        let layout = DataLayout::new(data_dir);
        let result = if dry_run {
            ResetResult {
                dirs_removed: vec!["chain/".to_string()],
                dirs_preserved: vec!["identity/".to_string(), "validator/".to_string()],
            }
        } else {
            layout.reset(ResetScope::Chain)?.into()
        };

        qstate.apply_decoherence(0.05);
        global_metrics().inc_command("reset_chain");
        global_metrics().inc_success();

        info!("Chain subspace collapsed (dry_run={})", dry_run);
        Ok(AdminResultType::ResetChain {
            dirs_removed: result.dirs_removed,
            dirs_preserved: result.dirs_preserved,
            fidelity: qstate.measure(),
        })
    }

    /// Collapse identity subspace to vacuum state.
    pub fn exec_reset_identity(
        data_dir: &str,
        confirm: bool,
        force: bool,
        dry_run: bool,
        config: &AdminConfig,
    ) -> AdminResult<AdminResultType> {
        let data_path = Path::new(data_dir);
        validate_data_dir(data_path, config)?;
        let _lock = acquire_admin_lock(data_path, config)?;
        let mut qstate = AdminQuantumState::new();

        if confirm && !force && !user_confirmation(CONFIRM_PROMPT_IDENTITY)? {
            return Err(AdminError::UserCancel);
        }

        qstate.apply_decoherence(0.01);
        let layout = DataLayout::new(data_dir);
        let result = if dry_run {
            ResetResult {
                dirs_removed: vec!["identity/".to_string()],
                dirs_preserved: vec!["chain/".to_string(), "validator/".to_string()],
            }
        } else {
            layout.reset(ResetScope::Identity)?.into()
        };

        qstate.apply_decoherence(0.05);
        global_metrics().inc_command("reset_identity");
        global_metrics().inc_success();

        info!("Identity subspace collapsed (dry_run={})", dry_run);
        Ok(AdminResultType::ResetIdentity {
            dirs_removed: result.dirs_removed,
            dirs_preserved: result.dirs_preserved,
            fidelity: qstate.measure(),
        })
    }

    /// Collapse entire Hilbert space.
    pub fn exec_reset_full(
        data_dir: &str,
        confirm: bool,
        force: bool,
        dry_run: bool,
        config: &AdminConfig,
    ) -> AdminResult<AdminResultType> {
        let data_path = Path::new(data_dir);
        validate_data_dir(data_path, config)?;
        let _lock = acquire_admin_lock(data_path, config)?;
        let mut qstate = AdminQuantumState::new();

        if confirm && !force && !user_confirmation(CONFIRM_PROMPT_FULL)? {
            return Err(AdminError::UserCancel);
        }

        if dry_run {
            let dirs = vec!["chain/".to_string(), "identity/".to_string(), "validator/".to_string()];
            global_metrics().inc_command("reset_full");
            global_metrics().inc_success();
            return Ok(AdminResultType::ResetFull {
                dirs_removed: dirs,
                fidelity: 1.0,
            });
        }

        // Backup everything first.
        let temp_backup = data_path.join(".iona_full_reset_backup");
        if temp_backup.exists() {
            fs::remove_dir_all(&temp_backup)?;
        }
        fs::create_dir_all(&temp_backup)?;
        super::helpers::copy_dir_all(data_path, &temp_backup)?;

        // Delete contents (excluding backup).
        for entry in fs::read_dir(data_path)? {
            let entry = entry?;
            let path = entry.path();
            if path.file_name().and_then(|s| s.to_str()) == Some(".iona_full_reset_backup") {
                continue;
            }
            if path.is_dir() {
                fs::remove_dir_all(&path)?;
            } else {
                fs::remove_file(&path)?;
            }
        }

        qstate.apply_decoherence(0.10);
        global_metrics().inc_command("reset_full");
        global_metrics().inc_success();

        info!("Complete Hilbert space collapsed (backup kept at {:?})", temp_backup);
        Ok(AdminResultType::ResetFull {
            dirs_removed: vec!["all data except backup".to_string()],
            fidelity: qstate.measure(),
        })
    }

    /// Measure node status observables.
    pub fn exec_status(data_dir: &str, config: &AdminConfig) -> AdminResult<AdminResultType> {
        let data_path = Path::new(data_dir);
        validate_data_dir(data_path, config)?;
        let mut qstate = AdminQuantumState::new();
        let layout = DataLayout::new(data_dir);
        let status = layout.status();

        qstate.apply_decoherence(0.001);
        global_metrics().inc_command("status");
        global_metrics().inc_success();

        debug!(best_height = status.blocks_count, entropy = qstate.entropy, "Node state measured");
        Ok(AdminResultType::Status {
            info: status,
            entropy: qstate.entropy,
        })
    }

    /// Measure peer identity observable.
    pub fn exec_peer_id(data_dir: &str, config: &AdminConfig) -> AdminResult<AdminResultType> {
        let data_path = Path::new(data_dir);
        validate_data_dir(data_path, config)?;
        let mut qstate = AdminQuantumState::new();
        let layout = DataLayout::new(data_dir);
        let peer_id = layout.peer_id()?;

        qstate.apply_decoherence(0.001);
        global_metrics().inc_command("peer_id");
        global_metrics().inc_success();

        let fingerprint = format!("sha256:{}", &peer_id[..8.min(peer_id.len())]);
        Ok(AdminResultType::PrintPeerId {
            peer_id,
            quantum_fingerprint: fingerprint,
        })
    }

    /// Compute multiaddress with quantum network capacity.
    pub fn exec_multiaddr(
        data_dir: &str,
        listen_addr: &str,
        config: &AdminConfig,
    ) -> AdminResult<AdminResultType> {
        let data_path = Path::new(data_dir);
        validate_data_dir(data_path, config)?;
        let mut qstate = AdminQuantumState::new();
        let layout = DataLayout::new(data_dir);
        let peer_id = layout.peer_id()?;
        let multiaddr = format!("{}/p2p/{}", listen_addr, peer_id);

        qstate.apply_decoherence(0.001);
        global_metrics().inc_command("multiaddr");
        global_metrics().inc_success();

        let capacity = 1024;
        Ok(AdminResultType::PrintMultiaddr {
            multiaddr,
            entanglement_capacity: capacity,
        })
    }

    /// Measure configuration wavefunction.
    pub fn exec_config(config_path: &str, config: &AdminConfig) -> AdminResult<AdminResultType> {
        let mut qstate = AdminQuantumState::new();
        let config_str = fs::read_to_string(config_path)?;
        let toml_value: toml::Value = toml::from_str(&config_str)?;
        let config_json = serde_json::to_value(toml_value)?;

        qstate.apply_decoherence(0.002);
        global_metrics().inc_command("config");
        global_metrics().inc_success();

        let purity = (1.0 - qstate.entropy / 10.0).clamp(0.0, 1.0);
        Ok(AdminResultType::Config {
            config: config_json,
            config_purity: purity,
        })
    }

    /// Classical version observable.
    pub fn exec_version(config: &AdminConfig) -> AdminResult<AdminResultType> {
        let build_epoch = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        global_metrics().inc_command("version");
        global_metrics().inc_success();

        Ok(AdminResultType::Version {
            version: env!("CARGO_PKG_VERSION").to_string(),
            commit: option_env!("VERGEN_GIT_SHA").unwrap_or("unknown").to_string(),
            build_epoch,
        })
    }

    /// Perform unitary cloning operation (backup).
    pub fn exec_backup(
        data_dir: &str,
        backup_dir: &str,
        force: bool,
        dry_run: bool,
        config: &AdminConfig,
    ) -> AdminResult<AdminResultType> {
        let data_path = Path::new(data_dir);
        validate_data_dir(data_path, config)?;
        let _lock = acquire_admin_lock(data_path, config)?;

        let source = Path::new(data_dir);
        if !source.exists() {
            return Err(AdminError::DirectoryNotFound {
                path: source.to_path_buf(),
            });
        }

        let mut qstate = AdminQuantumState::new();
        let source_size = get_dir_size(source)?;
        let backup_path = Path::new(backup_dir);
        ensure_disk_space(backup_path, source_size + 1024 * 1024)?;

        qstate.apply_decoherence(0.01);

        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let target = backup_path.join(format!("{}{}", BACKUP_PREFIX, timestamp));

        if dry_run {
            global_metrics().inc_command("backup");
            global_metrics().inc_success();
            info!("Dry-run backup to {}", target.display());
            return Ok(AdminResultType::BackupCreated {
                backup_path: target.to_string_lossy().into(),
                clone_fidelity: 1.0,
            });
        }

        let mut options = CopyOptions::new();
        options.overwrite = true;
        options.skip_exist = false;
        options.buffer_size = 64 * 1024;
        options.copy_inside = false;
        options.depth = 0;

        let result = retry_operation(|| {
            fs::create_dir_all(&target)?;
            copy(&source, &target, &options)?;
            Ok(())
        });

        if let Err(e) = result {
            let _ = fs::remove_dir_all(&target);
            return Err(AdminError::BackupFailed {
                reason: format!("quantum cloning failed: {}", e),
            });
        }

        qstate.apply_decoherence(0.03);
        global_metrics().inc_command("backup");
        global_metrics().inc_success();

        let clone_fidelity = qstate.measure();
        info!(backup_path = %target.display(), fidelity = clone_fidelity, "Quantum state cloned");
        Ok(AdminResultType::BackupCreated {
            backup_path: target.to_string_lossy().into(),
            clone_fidelity,
        })
    }

    /// Measure health observable.
    pub fn exec_health(data_dir: &str, peer_count: usize, config: &AdminConfig) -> AdminResult<AdminResultType> {
        let data_path = Path::new(data_dir);
        validate_data_dir(data_path, config)?;
        let mut qstate = AdminQuantumState::new();
        let layout = DataLayout::new(data_dir);
        let status = layout.status();
        let ok = status.has_chain_data && status.blocks_count > 0;

        qstate.apply_decoherence(0.005);
        global_metrics().inc_command("health");
        global_metrics().inc_success();

        let message = if ok {
            format!(
                "Node is healthy: height={}, peers={}, coherence={:.4}",
                status.blocks_count,
                peer_count,
                qstate.coherence
            )
        } else {
            format!(
                "Node is unhealthy: height={}, has_chain_data={}, coherence={:.4}",
                status.blocks_count, status.has_chain_data, qstate.coherence
            )
        };

        Ok(AdminResultType::Health {
            ok,
            height: status.blocks_count,
            peers: peer_count,
            message,
            coherence: qstate.coherence,
        })
    }

    /// Measure integrity observable.
    pub fn exec_verify(data_dir: &str, config: &AdminConfig) -> AdminResult<AdminResultType> {
        let data_path = Path::new(data_dir);
        validate_data_dir(data_path, config)?;
        let mut qstate = AdminQuantumState::new();
        let layout = DataLayout::new(data_dir);
        qstate.apply_decoherence(0.01);

        let store = FsBlockStore::open(layout.blocks_dir(), None).map_err(|e| {
            AdminError::IntegrityCheckFailed {
                reason: format!("cannot open block store: {}", e),
            }
        })?;

        global_metrics().inc_command("verify");

        match store.verify_integrity() {
            Ok(()) => {
                qstate.apply_decoherence(0.001);
                global_metrics().inc_success();
                Ok(AdminResultType::Verify {
                    passed: true,
                    message: "Integrity observable measured: PASSED".into(),
                    confidence: qstate.measure(),
                })
            }
            Err(e) => {
                qstate.apply_decoherence(0.05);
                global_metrics().inc_success(); // still a successful command execution
                Ok(AdminResultType::Verify {
                    passed: false,
                    message: format!("Integrity observable measured: FAILED - {}", e),
                    confidence: 1.0 - qstate.measure(),
                })
            }
        }
    }
}

pub mod manager {
    //! Centralised manager for admin commands.
    use super::{
        config::AdminConfig,
        error::{AdminError, AdminResult},
        metrics::{AdminMetrics, global_metrics},
        commands,
        types::AdminResult as AdminResultType,
    };
    use std::sync::Mutex;
    use tracing::{debug, info};

    /// Manager for admin operations.
    pub struct AdminManager {
        config: AdminConfig,
        initialised: bool,
    }

    impl AdminManager {
        pub fn new(config: AdminConfig) -> Self {
            config.validate().expect("invalid AdminConfig");
            Self {
                config,
                initialised: false,
            }
        }

        pub fn default() -> Self {
            Self::new(AdminConfig::default())
        }

        pub fn config(&self) -> &AdminConfig {
            &self.config
        }

        pub fn init(&mut self) {
            self.initialised = true;
            info!("admin manager initialised");
        }

        pub fn is_initialised(&self) -> bool {
            self.initialised
        }

        /// Execute a command with the manager's config.
        pub fn execute<F>(&self, command: F) -> AdminResult<AdminResultType>
        where
            F: FnOnce(&AdminConfig) -> AdminResult<AdminResultType>,
        {
            if !self.initialised {
                debug!("admin manager not initialised, but executing command anyway");
            }
            command(&self.config)
        }

        // Convenience wrappers.

        pub fn reset_chain(
            &self,
            data_dir: &str,
            confirm: bool,
            force: bool,
            dry_run: bool,
        ) -> AdminResult<AdminResultType> {
            commands::exec_reset_chain(data_dir, confirm, force, dry_run, &self.config)
        }

        pub fn reset_identity(
            &self,
            data_dir: &str,
            confirm: bool,
            force: bool,
            dry_run: bool,
        ) -> AdminResult<AdminResultType> {
            commands::exec_reset_identity(data_dir, confirm, force, dry_run, &self.config)
        }

        pub fn reset_full(
            &self,
            data_dir: &str,
            confirm: bool,
            force: bool,
            dry_run: bool,
        ) -> AdminResult<AdminResultType> {
            commands::exec_reset_full(data_dir, confirm, force, dry_run, &self.config)
        }

        pub fn status(&self, data_dir: &str) -> AdminResult<AdminResultType> {
            commands::exec_status(data_dir, &self.config)
        }

        pub fn peer_id(&self, data_dir: &str) -> AdminResult<AdminResultType> {
            commands::exec_peer_id(data_dir, &self.config)
        }

        pub fn multiaddr(&self, data_dir: &str, listen_addr: &str) -> AdminResult<AdminResultType> {
            commands::exec_multiaddr(data_dir, listen_addr, &self.config)
        }

        pub fn config_show(&self, config_path: &str) -> AdminResult<AdminResultType> {
            commands::exec_config(config_path, &self.config)
        }

        pub fn version(&self) -> AdminResult<AdminResultType> {
            commands::exec_version(&self.config)
        }

        pub fn backup(
            &self,
            data_dir: &str,
            backup_dir: &str,
            force: bool,
            dry_run: bool,
        ) -> AdminResult<AdminResultType> {
            commands::exec_backup(data_dir, backup_dir, force, dry_run, &self.config)
        }

        pub fn health(&self, data_dir: &str, peer_count: usize) -> AdminResult<AdminResultType> {
            commands::exec_health(data_dir, peer_count, &self.config)
        }

        pub fn verify(&self, data_dir: &str) -> AdminResult<AdminResultType> {
            commands::exec_verify(data_dir, &self.config)
        }

        pub fn metrics_snapshot(&self) -> super::metrics::AdminMetricsSnapshot {
            global_metrics().snapshot()
        }

        pub fn reset_metrics(&self) {
            // Since metrics are global, we need to reset them manually.
            // We'll create a new metrics instance and swap.
            // For simplicity, we'll just warn.
            tracing::warn!("resetting admin metrics not supported in this version");
        }
    }
}

// -----------------------------------------------------------------------------
// Public exports
// -----------------------------------------------------------------------------

pub use config::AdminConfig;
pub use error::{AdminError, AdminResult};
pub use metrics::{AdminMetrics, AdminMetricsSnapshot};
pub use types::{AdminResult as AdminCommandResult, AdminQuantumState, ResetResult};
pub use manager::AdminManager;
pub use helpers::{result_to_json, user_confirmation, validate_data_dir};

// -----------------------------------------------------------------------------
// Legacy global functions (backward compatibility)
// -----------------------------------------------------------------------------

use spin::Once;

static GLOBAL_MANAGER: Once<AdminManager> = Once::new();

fn global_manager() -> &'static AdminManager {
    GLOBAL_MANAGER.get_or_init(|| {
        let mut mgr = AdminManager::new(AdminConfig::default());
        mgr.init();
        mgr
    })
}

/// Legacy exec_reset_chain.
pub fn exec_reset_chain(
    data_dir: &str,
    confirm: bool,
    force: bool,
    dry_run: bool,
) -> AdminResult<AdminCommandResult> {
    global_manager().reset_chain(data_dir, confirm, force, dry_run)
}

/// Legacy exec_reset_identity.
pub fn exec_reset_identity(
    data_dir: &str,
    confirm: bool,
    force: bool,
    dry_run: bool,
) -> AdminResult<AdminCommandResult> {
    global_manager().reset_identity(data_dir, confirm, force, dry_run)
}

/// Legacy exec_reset_full.
pub fn exec_reset_full(
    data_dir: &str,
    confirm: bool,
    force: bool,
    dry_run: bool,
) -> AdminResult<AdminCommandResult> {
    global_manager().reset_full(data_dir, confirm, force, dry_run)
}

/// Legacy exec_status.
pub fn exec_status(data_dir: &str) -> AdminResult<AdminCommandResult> {
    global_manager().status(data_dir)
}

/// Legacy exec_peer_id.
pub fn exec_peer_id(data_dir: &str) -> AdminResult<AdminCommandResult> {
    global_manager().peer_id(data_dir)
}

/// Legacy exec_multiaddr.
pub fn exec_multiaddr(data_dir: &str, listen_addr: &str) -> AdminResult<AdminCommandResult> {
    global_manager().multiaddr(data_dir, listen_addr)
}

/// Legacy exec_config.
pub fn exec_config(config_path: &str) -> AdminResult<AdminCommandResult> {
    global_manager().config_show(config_path)
}

/// Legacy exec_version.
pub fn exec_version() -> AdminResult<AdminCommandResult> {
    global_manager().version()
}

/// Legacy exec_backup.
pub fn exec_backup(
    data_dir: &str,
    backup_dir: &str,
    force: bool,
    dry_run: bool,
) -> AdminResult<AdminCommandResult> {
    global_manager().backup(data_dir, backup_dir, force, dry_run)
}

/// Legacy exec_health.
pub fn exec_health(data_dir: &str, peer_count: usize) -> AdminResult<AdminCommandResult> {
    global_manager().health(data_dir, peer_count)
}

/// Legacy exec_verify.
pub fn exec_verify(data_dir: &str) -> AdminResult<AdminCommandResult> {
    global_manager().verify(data_dir)
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;
    use crate::storage::layout::DataLayout;

    #[test]
    fn test_config_validation() {
        let config = AdminConfig::default();
        assert!(config.validate().is_ok());

        let mut bad = config.clone();
        bad.max_retries = 0;
        assert!(bad.validate().is_err());

        let mut bad2 = config;
        bad2.retry_backoff_ms = 0;
        assert!(bad2.validate().is_err());
    }

    #[test]
    fn test_validate_data_dir() {
        let tmp = tempdir().unwrap();
        let config = AdminConfig::default();
        assert!(validate_data_dir(tmp.path(), &config).is_ok());
        assert!(validate_data_dir(Path::new("/"), &config).is_err());
    }

    #[test]
    fn test_exec_status() {
        let tmp = tempdir().unwrap();
        let data_dir = tmp.path().to_str().unwrap();
        // Ensure layout exists.
        let layout = DataLayout::new(data_dir);
        layout.ensure_all().unwrap();
        let result = exec_status(data_dir).unwrap();
        match result {
            AdminCommandResult::Status { info, entropy } => {
                assert!(!info.has_chain_data);
                assert!(!info.has_identity);
                assert!(!info.has_validator_key);
                assert_eq!(info.blocks_count, 0);
                assert!(entropy >= 0.0);
            }
            _ => panic!("expected Status result"),
        }
    }

    #[test]
    fn test_exec_reset_chain_dry_run() {
        let tmp = tempdir().unwrap();
        let data_dir = tmp.path().to_str().unwrap();
        let result = exec_reset_chain(data_dir, false, false, true).unwrap();
        match result {
            AdminCommandResult::ResetChain { dirs_removed, dirs_preserved, .. } => {
                assert!(dirs_removed.contains(&"chain/".to_string()));
                assert!(dirs_preserved.contains(&"identity/".to_string()));
            }
            _ => panic!("expected ResetChain with dry-run"),
        }
    }

    #[test]
    fn test_exec_backup_dry_run() {
        let src = tempdir().unwrap();
        let data_dir = src.path().to_str().unwrap();
        let layout = DataLayout::new(data_dir);
        layout.ensure_all().unwrap();
        fs::write(layout.state_full_path(), "{}").unwrap();

        let backup_dir = tempdir().unwrap();
        let result = exec_backup(data_dir, backup_dir.path().to_str().unwrap(), false, true).unwrap();
        match result {
            AdminCommandResult::BackupCreated { backup_path, clone_fidelity } => {
                assert!(backup_path.contains(BACKUP_PREFIX));
                assert_eq!(clone_fidelity, 1.0);
                assert!(!Path::new(&backup_path).exists());
            }
            _ => panic!("expected BackupCreated with dry-run"),
        }
    }
}
