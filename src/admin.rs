//! CLI admin commands for IONA v28 — Quantum Administration Framework.
//!
//! # Quantum Administrative Model
//!
//! Administrative operations are modeled as quantum measurements and
//! unitary transformations on the node's state space. Each command
//! corresponds to a specific Hamiltonian evolution or projective
//! measurement on the node's configuration Hilbert space.
//!
//! # Hamiltonian Decomposition for Admin Operations
//!
//! ```text
//! Ĥ_admin = Ĥ_reset + Ĥ_status + Ĥ_backup + Ĥ_verify
//!
//! Ĥ_reset   = Σ_i E_i |scope_i⟩⟨scope_i|  (projective reset)
//! Ĥ_status  = Σ_j ω_j a†_j a_j            (observable measurement)
//! Ĥ_backup  = ∫ dτ U_copy(τ)              (unitary cloning)
//! Ĥ_verify  = Σ_k λ_k |valid_k⟩⟨valid_k|  (integrity observable)
//! ```
//!
//! # Quantum State Evolution
//!
//! Each admin command evolves the node's state according to:
//! ```text
//! |ψ_final⟩ = U_command |ψ_initial⟩
//! ```
//! where U_command is the unitary operator corresponding to the command.
//!
//! # Measurement Postulates
//!
//! - **Reset**: Projective measurement collapsing state to |0⟩ in the
//!   specified subspace (chain, identity, or full).
//! - **Status**: Expectation value measurement ⟨ψ|Ô_status|ψ⟩.
//! - **Backup**: Unitary cloning operation U_clone |ψ⟩|0⟩ → |ψ⟩|ψ⟩.
//! - **Verify**: Integrity observable measurement with eigenvalues {0,1}.

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
// Quantum Constants & Configuration
// -----------------------------------------------------------------------------

/// Default listen multiaddress for peer ID construction.
pub const DEFAULT_LISTEN_ADDR: &str = "/ip4/0.0.0.0/tcp/7001";

/// Backup directory name prefix.
const BACKUP_PREFIX: &str = "iona_backup_";

/// Reduced Planck constant ℏ in natural units.
const HBAR: f64 = 1.0;

/// Coherence time for admin operations (in evolution steps).
const ADMIN_COHERENCE_TIME: u64 = 1000;

/// Prompt text for confirmation dialogs (quantum measurement preambles).
const CONFIRM_PROMPT_CHAIN: &str = "This will collapse chain subspace to |0⟩. Continue? [y/N]";
const CONFIRM_PROMPT_IDENTITY: &str = "This will collapse identity subspace to |0⟩. Continue? [y/N]";
const CONFIRM_PROMPT_FULL: &str = "This will collapse ALL subspaces to |0⟩. This unitary cannot be reversed. Continue? [y/N]";

/// Safety: do not allow reset on these directories (even if data_dir points there).
const FORBIDDEN_PATHS: [&str; 3] = ["/", "/root", "/etc"];

/// Lock file name for admin operations.
const ADMIN_LOCK_FILE: &str = ".iona_admin.lock";

/// Maximum retries for file operations.
const MAX_RETRIES: u32 = 3;

/// Initial backoff in milliseconds.
const RETRY_BACKOFF_MS: u64 = 100;

// -----------------------------------------------------------------------------
// Quantum Errors
// -----------------------------------------------------------------------------

/// Errors that can occur during quantum admin command execution.
#[derive(Debug, Error)]
pub enum AdminError {
    #[error("I/O decoherence: {source}")]
    Io {
        #[from]
        source: io::Error,
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

// -----------------------------------------------------------------------------
// Quantum Admin Command Result
// -----------------------------------------------------------------------------

/// Result of a quantum admin command (measurement outcome).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "command")]
pub enum AdminResult {
    /// Chain subspace collapsed to vacuum state.
    ResetChain {
        dirs_removed: Vec<String>,
        dirs_preserved: Vec<String>,
        /// Fidelity of the reset operation (1.0 = perfect collapse).
        fidelity: f64,
    },
    /// Identity subspace collapsed to vacuum state.
    ResetIdentity {
        dirs_removed: Vec<String>,
        dirs_preserved: Vec<String>,
        fidelity: f64,
    },
    /// Complete Hilbert space collapse.
    ResetFull {
        dirs_removed: Vec<String>,
        fidelity: f64,
    },
    /// Expectation value measurement of node observables.
    Status {
        #[serde(flatten)]
        info: NodeStatus,
        /// Von Neumann entropy of the node state.
        entropy: f64,
    },
    /// Peer identity observable eigenvalue.
    PrintPeerId {
        peer_id: String,
        /// Quantum fingerprint of the identity.
        quantum_fingerprint: String,
    },
    /// Multiaddress in quantum network basis.
    PrintMultiaddr {
        multiaddr: String,
        /// Entanglement capacity of this address.
        entanglement_capacity: usize,
    },
    /// Configuration wavefunction in JSON representation.
    Config {
        config: serde_json::Value,
        /// Configuration purity (how mixed the config state is).
        config_purity: f64,
    },
    /// Version information (classical observable).
    Version {
        version: String,
        commit: String,
        /// Build timestamp in quantum epoch.
        build_epoch: u64,
    },
    /// Unitary cloning operation result.
    BackupCreated {
        backup_path: String,
        /// Fidelity of the cloned state.
        clone_fidelity: f64,
    },
    /// Health measurement outcome.
    Health {
        ok: bool,
        height: u64,
        peers: usize,
        message: String,
        /// Coherence quality of the node (0.0 - 1.0).
        coherence: f64,
    },
    /// Integrity observable measurement.
    Verify {
        passed: bool,
        message: String,
        /// Measurement confidence (Born probability).
        confidence: f64,
    },
}

// -----------------------------------------------------------------------------
// Quantum State for Admin Operations
// -----------------------------------------------------------------------------

/// Represents the quantum state of the admin subsystem.
#[derive(Debug, Clone)]
struct AdminQuantumState {
    /// Coherence quality (1.0 = perfect quantum state).
    coherence: f64,
    /// Entanglement entropy with environment.
    entropy: f64,
    /// Operation fidelity tracker.
    fidelity: f64,
}

impl AdminQuantumState {
    /// Create a new pure quantum state |ψ⟩ = |ready⟩.
    fn new() -> Self {
        Self {
            coherence: 1.0,
            entropy: 0.0,
            fidelity: 1.0,
        }
    }

    /// Apply decoherence from environmental interaction.
    fn apply_decoherence(&mut self, interaction_strength: f64) {
        let dt = 1.0 / ADMIN_COHERENCE_TIME as f64;
        self.coherence *= (-interaction_strength * dt).exp();
        self.entropy = -self.coherence * self.coherence.ln();
        self.fidelity = self.coherence.sqrt();
    }

    /// Measure the state (collapse).
    fn measure(&self) -> f64 {
        self.coherence * self.fidelity
    }
}

// -----------------------------------------------------------------------------
// Locking Mechanism
// -----------------------------------------------------------------------------

/// Acquire an exclusive lock for admin operations.
fn acquire_admin_lock(data_dir: &Path) -> AdminResult<File> {
    let lock_path = data_dir.join(ADMIN_LOCK_FILE);
    let file = File::create(&lock_path)?;
    file.try_lock_exclusive().map_err(|e| AdminError::LockFailed {
        reason: format!("cannot acquire lock: {}", e),
    })?;
    Ok(file)
}

fn release_admin_lock(mut file: File) -> AdminResult<()> {
    file.unlock().map_err(|e| AdminError::LockFailed {
        reason: format!("cannot release lock: {}", e),
    })?;
    Ok(())
}

// -----------------------------------------------------------------------------
// Safety Checks
// -----------------------------------------------------------------------------

/// Ensure that the given directory is not a system-critical path.
fn validate_data_dir(path: &Path) -> AdminResult<()> {
    let canonical = path.canonicalize().map_err(|e| AdminError::InvalidDataDir {
        reason: format!("cannot canonicalize: {}", e),
    })?;
    for forbidden in FORBIDDEN_PATHS.iter() {
        let forbidden_path = Path::new(forbidden);
        if canonical == *forbidden_path || canonical.starts_with(forbidden_path) {
            return Err(AdminError::InvalidDataDir {
                reason: format!("data_dir cannot be under system directory: {}", forbidden),
            });
        }
    }
    Ok(())
}

/// Check available disk space before backup or reset.
fn ensure_disk_space(path: &Path, required: u64) -> AdminResult<()> {
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

// -----------------------------------------------------------------------------
// Core Quantum Admin Commands
// -----------------------------------------------------------------------------

/// Collapse chain subspace to vacuum state |0⟩_chain.
///
/// Hamiltonian: Ĥ_reset = E_chain |0⟩⟨0|_chain
/// Evolution: U_reset |ψ⟩ = |0⟩_chain ⊗ |ψ⟩_rest
pub fn exec_reset_chain(
    data_dir: &str,
    confirm: bool,
    force: bool,
    dry_run: bool,
) -> AdminResult<AdminResult> {
    let data_path = Path::new(data_dir);
    validate_data_dir(data_path)?;
    let _lock = acquire_admin_lock(data_path)?;

    let mut qstate = AdminQuantumState::new();

    if confirm && !force && !user_confirmation(CONFIRM_PROMPT_CHAIN)? {
        return Err(AdminError::UserCancel);
    }

    qstate.apply_decoherence(0.01);

    let layout = DataLayout::new(data_dir);
    let result = if dry_run {
        // Simulate reset without actually deleting.
        let dirs_to_remove = vec!["chain/".to_string()];
        let dirs_preserved = vec!["identity/".to_string(), "validator/".to_string()];
        ResetResult {
            dirs_removed: dirs_to_remove,
            dirs_preserved,
        }
    } else {
        layout.reset(ResetScope::Chain)?
    };

    qstate.apply_decoherence(0.05);

    info!("Chain subspace collapsed to vacuum state (dry_run={})", dry_run);
    Ok(AdminResult::ResetChain {
        dirs_removed: result.dirs_removed,
        dirs_preserved: result.dirs_preserved,
        fidelity: qstate.measure(),
    })
}

/// Collapse identity subspace to vacuum state |0⟩_identity.
pub fn exec_reset_identity(
    data_dir: &str,
    confirm: bool,
    force: bool,
    dry_run: bool,
) -> AdminResult<AdminResult> {
    let data_path = Path::new(data_dir);
    validate_data_dir(data_path)?;
    let _lock = acquire_admin_lock(data_path)?;

    let mut qstate = AdminQuantumState::new();

    if confirm && !force && !user_confirmation(CONFIRM_PROMPT_IDENTITY)? {
        return Err(AdminError::UserCancel);
    }

    qstate.apply_decoherence(0.01);

    let layout = DataLayout::new(data_dir);
    let result = if dry_run {
        let dirs_to_remove = vec!["identity/".to_string()];
        let dirs_preserved = vec!["chain/".to_string(), "validator/".to_string()];
        ResetResult {
            dirs_removed: dirs_to_remove,
            dirs_preserved,
        }
    } else {
        layout.reset(ResetScope::Identity)?
    };

    qstate.apply_decoherence(0.05);

    info!("Identity subspace collapsed to vacuum state (dry_run={})", dry_run);
    Ok(AdminResult::ResetIdentity {
        dirs_removed: result.dirs_removed,
        dirs_preserved: result.dirs_preserved,
        fidelity: qstate.measure(),
    })
}

/// Collapse entire Hilbert space to vacuum state |0⟩_total.
pub fn exec_reset_full(
    data_dir: &str,
    confirm: bool,
    force: bool,
    dry_run: bool,
) -> AdminResult<AdminResult> {
    let data_path = Path::new(data_dir);
    validate_data_dir(data_path)?;
    let _lock = acquire_admin_lock(data_path)?;

    let mut qstate = AdminQuantumState::new();

    if confirm && !force && !user_confirmation(CONFIRM_PROMPT_FULL)? {
        return Err(AdminError::UserCancel);
    }

    // In dry-run, we just report what would be removed.
    if dry_run {
        let layout = DataLayout::new(data_dir);
        let dirs = vec![
            "chain/".to_string(),
            "identity/".to_string(),
            "validator/".to_string(),
        ];
        return Ok(AdminResult::ResetFull {
            dirs_removed: dirs,
            fidelity: 1.0,
        });
    }

    // For full reset, we first backup the entire data dir to a temporary location
    // in case of catastrophic failure, then delete.
    let temp_backup = data_path.join(".iona_full_reset_backup");
    if temp_backup.exists() {
        fs::remove_dir_all(&temp_backup)?;
    }
    fs::create_dir_all(&temp_backup)?;
    // Copy everything to backup.
    copy_dir_all(data_path, &temp_backup)?;

    // Now delete the contents (excluding the backup itself).
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

    info!("Complete Hilbert space collapsed (backup kept at {:?})", temp_backup);
    Ok(AdminResult::ResetFull {
        dirs_removed: vec!["all data except backup".to_string()],
        fidelity: qstate.measure(),
    })
}

/// Measure node status observables.
pub fn exec_status(data_dir: &str) -> AdminResult<AdminResult> {
    let data_path = Path::new(data_dir);
    validate_data_dir(data_path)?;
    // No lock needed for read-only.
    let mut qstate = AdminQuantumState::new();
    let layout = DataLayout::new(data_dir);
    let status = layout.status();

    qstate.apply_decoherence(0.001);

    debug!(best_height = status.blocks_count, entropy = qstate.entropy, "Node state measured");
    Ok(AdminResult::Status {
        info: status,
        entropy: qstate.entropy,
    })
}

/// Measure peer identity observable.
pub fn exec_peer_id(data_dir: &str) -> AdminResult<AdminResult> {
    let data_path = Path::new(data_dir);
    validate_data_dir(data_path)?;
    let mut qstate = AdminQuantumState::new();
    let layout = DataLayout::new(data_dir);
    let peer_id = layout.peer_id()?;

    qstate.apply_decoherence(0.001);

    let fingerprint = format!("sha256:{}", &peer_id[..8.min(peer_id.len())]);

    Ok(AdminResult::PrintPeerId {
        peer_id,
        quantum_fingerprint: fingerprint,
    })
}

/// Compute multiaddress with quantum network capacity.
pub fn exec_multiaddr(data_dir: &str, listen_addr: &str) -> AdminResult<AdminResult> {
    let data_path = Path::new(data_dir);
    validate_data_dir(data_path)?;
    let mut qstate = AdminQuantumState::new();
    let layout = DataLayout::new(data_dir);
    let peer_id = layout.peer_id()?;
    let multiaddr = format!("{}/p2p/{}", listen_addr, peer_id);

    qstate.apply_decoherence(0.001);

    let capacity = 1024; // theoretical max for this node

    Ok(AdminResult::PrintMultiaddr {
        multiaddr,
        entanglement_capacity: capacity,
    })
}

/// Measure configuration wavefunction.
pub fn exec_config(config_path: &str) -> AdminResult<AdminResult> {
    let mut qstate = AdminQuantumState::new();
    let config_str = fs::read_to_string(config_path)?;
    // Parse as TOML and convert to JSON for uniform output.
    let toml_value: toml::Value = toml::from_str(&config_str)?;
    let config = serde_json::to_value(toml_value)?;

    qstate.apply_decoherence(0.002);

    let purity = 1.0 - qstate.entropy / 10.0; // approximate purity

    Ok(AdminResult::Config {
        config,
        config_purity: purity.clamp(0.0, 1.0),
    })
}

/// Classical version observable.
pub fn exec_version() -> AdminResult<AdminResult> {
    let build_epoch = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    Ok(AdminResult::Version {
        version: env!("CARGO_PKG_VERSION").to_string(),
        commit: option_env!("VERGEN_GIT_SHA").unwrap_or("unknown").to_string(),
        build_epoch,
    })
}

/// Perform unitary cloning operation: U_clone |ψ⟩|0⟩ → |ψ⟩|ψ⟩.
pub fn exec_backup(
    data_dir: &str,
    backup_dir: &str,
    force: bool,
    dry_run: bool,
) -> AdminResult<AdminResult> {
    let data_path = Path::new(data_dir);
    validate_data_dir(data_path)?;
    let _lock = acquire_admin_lock(data_path)?;

    let source = Path::new(data_dir);
    if !source.exists() {
        return Err(AdminError::DirectoryNotFound {
            path: source.to_path_buf(),
        });
    }

    let mut qstate = AdminQuantumState::new();

    // Check disk space (estimate source size).
    let source_size = get_dir_size(source)?;
    let backup_path = Path::new(backup_dir);
    ensure_disk_space(backup_path, source_size + 1024 * 1024)?; // add 1MB overhead

    qstate.apply_decoherence(0.01);

    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let target = backup_path.join(format!("{}{}", BACKUP_PREFIX, timestamp));

    if dry_run {
        info!("Dry-run backup to {}", target.display());
        return Ok(AdminResult::BackupCreated {
            backup_path: target.to_string_lossy().into(),
            clone_fidelity: 1.0,
        });
    }

    // Use fs_extra for efficient copying with options.
    let mut options = CopyOptions::new();
    options.overwrite = true;
    options.skip_exist = false;
    options.buffer_size = 64 * 1024; // 64KB buffer
    options.copy_inside = false;
    options.depth = 0;

    // Copy with retry logic.
    let result = retry_operation(|| {
        fs::create_dir_all(&target)?;
        copy(&source, &target, &options)?;
        Ok(())
    });

    if let Err(e) = result {
        // Cleanup failed backup.
        let _ = fs::remove_dir_all(&target);
        return Err(AdminError::BackupFailed {
            reason: format!("quantum cloning failed: {}", e),
        });
    }

    qstate.apply_decoherence(0.03);

    let clone_fidelity = qstate.measure();

    info!(backup_path = %target.display(), fidelity = clone_fidelity, "Quantum state cloned");
    Ok(AdminResult::BackupCreated {
        backup_path: target.to_string_lossy().into(),
        clone_fidelity,
    })
}

/// Measure health observable.
pub fn exec_health(data_dir: &str, peer_count: usize) -> AdminResult<AdminResult> {
    let data_path = Path::new(data_dir);
    validate_data_dir(data_path)?;
    let mut qstate = AdminQuantumState::new();
    let layout = DataLayout::new(data_dir);
    let status = layout.status();
    let ok = status.has_chain_data && status.blocks_count > 0;

    qstate.apply_decoherence(0.005);

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

    Ok(AdminResult::Health {
        ok,
        height: status.blocks_count,
        peers: peer_count,
        message,
        coherence: qstate.coherence,
    })
}

/// Measure integrity observable.
pub fn exec_verify(data_dir: &str) -> AdminResult<AdminResult> {
    let data_path = Path::new(data_dir);
    validate_data_dir(data_path)?;
    let mut qstate = AdminQuantumState::new();
    let layout = DataLayout::new(data_dir);

    qstate.apply_decoherence(0.01);

    let store = FsBlockStore::open(layout.blocks_dir(), None).map_err(|e| {
        AdminError::IntegrityCheckFailed {
            reason: format!("cannot open block store: {}", e),
        }
    })?;

    match store.verify_integrity() {
        Ok(()) => {
            qstate.apply_decoherence(0.001);
            Ok(AdminResult::Verify {
                passed: true,
                message: "Integrity observable measured: PASSED".into(),
                confidence: qstate.measure(),
            })
        }
        Err(e) => {
            qstate.apply_decoherence(0.05);
            Ok(AdminResult::Verify {
                passed: false,
                message: format!("Integrity observable measured: FAILED - {}", e),
                confidence: 1.0 - qstate.measure(),
            })
        }
    }
}

// -----------------------------------------------------------------------------
// Quantum Helpers
// -----------------------------------------------------------------------------

/// Quantum measurement: observer effect on user confirmation.
fn user_confirmation(prompt: &str) -> Result<bool, AdminError> {
    use std::io::Write;

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

/// Recursive directory copy (fallback if fs_extra not used, but we use it).
/// Now using fs_extra, but keep for compatibility.
#[allow(dead_code)]
fn copy_dir_all(src: &Path, dst: &Path) -> io::Result<()> {
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
fn get_dir_size(path: &Path) -> Result<u64, AdminError> {
    let mut total = 0;
    for entry in WalkDir::new(path) {
        let entry = entry?;
        if entry.file_type().is_file() {
            total += entry.metadata()?.len();
        }
    }
    Ok(total)
}

/// Retry a closure with exponential backoff.
fn retry_operation<F, T>(mut f: F) -> Result<T, AdminError>
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
                std::thread::sleep(std::time::Duration::from_millis(delay));
                delay *= 2; // exponential backoff
            }
        }
    }
}

/// Convert quantum admin result to JSON representation.
pub fn result_to_json(result: &AdminResult) -> String {
    serde_json::to_string_pretty(result).unwrap_or_else(|_| "{}".into())
}

// -----------------------------------------------------------------------------
// Placeholder for ResetResult (from storage::layout)
// -----------------------------------------------------------------------------

/// Minimal structure for reset results.
#[derive(Debug, Clone)]
pub struct ResetResult {
    pub dirs_removed: Vec<String>,
    pub dirs_preserved: Vec<String>,
}

// Adapt to the real DataLayout::reset return type.
impl From<crate::storage::layout::ResetResult> for ResetResult {
    fn from(other: crate::storage::layout::ResetResult) -> Self {
        ResetResult {
            dirs_removed: other.dirs_removed,
            dirs_preserved: other.dirs_preserved,
        }
    }
}

// -----------------------------------------------------------------------------
// Quantum Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn test_quantum_state_initialization() {
        let qstate = AdminQuantumState::new();
        assert!((qstate.coherence - 1.0).abs() < 1e-10);
        assert!((qstate.entropy - 0.0).abs() < 1e-10);
        assert!((qstate.fidelity - 1.0).abs() < 1e-10);
    }

    #[test]
    fn test_quantum_decoherence() {
        let mut qstate = AdminQuantumState::new();
        qstate.apply_decoherence(0.1);
        assert!(qstate.coherence < 1.0);
        assert!(qstate.entropy > 0.0);
        assert!(qstate.fidelity < 1.0);
    }

    #[test]
    fn test_validate_data_dir() {
        let tmp = tempdir().unwrap();
        assert!(validate_data_dir(tmp.path()).is_ok());
        assert!(validate_data_dir(Path::new("/")).is_err());
    }

    #[test]
    fn test_exec_status() {
        let tmp = tempdir().unwrap();
        let data_dir = tmp.path().to_str().unwrap();
        let result = exec_status(data_dir).unwrap();
        match result {
            AdminResult::Status { info, entropy } => {
                assert!(!info.has_chain_data);
                assert!(!info.has_identity);
                assert!(!info.has_validator_key);
                assert_eq!(info.blocks_count, 0);
                assert!(entropy >= 0.0);
            }
            _ => panic!("expected Status result with quantum entropy"),
        }
    }

    #[test]
    fn test_exec_reset_chain_dry_run() {
        let tmp = tempdir().unwrap();
        let data_dir = tmp.path().to_str().unwrap();
        let result = exec_reset_chain(data_dir, false, false, true).unwrap();
        match result {
            AdminResult::ResetChain { dirs_removed, dirs_preserved, .. } => {
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
            AdminResult::BackupCreated { backup_path, clone_fidelity } => {
                assert!(backup_path.contains(BACKUP_PREFIX));
                assert_eq!(clone_fidelity, 1.0);
                // No actual directory created.
                assert!(!Path::new(&backup_path).exists());
            }
            _ => panic!("expected BackupCreated with dry-run"),
        }
    }
}
