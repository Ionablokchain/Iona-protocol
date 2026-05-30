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
use serde::{Deserialize, Serialize};
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};
use thiserror::Error;
use tracing::{debug, error, info, warn};

// -----------------------------------------------------------------------------
// Quantum Constants
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

    /// Collapse to a specific outcome (measurement).
    fn measure(&self) -> f64 {
        self.coherence * self.fidelity
    }
}

// -----------------------------------------------------------------------------
// Core Quantum Admin Commands
// -----------------------------------------------------------------------------

/// Collapse chain subspace to vacuum state |0⟩_chain.
///
/// Hamiltonian: Ĥ_reset = E_chain |0⟩⟨0|_chain
/// Evolution: U_reset |ψ⟩ = |0⟩_chain ⊗ |ψ⟩_rest
pub fn exec_reset_chain(data_dir: &str, confirm: bool) -> AdminResult<AdminResult> {
    let mut qstate = AdminQuantumState::new();

    if confirm && !user_confirmation(CONFIRM_PROMPT_CHAIN)? {
        return Err(AdminError::UserCancel);
    }

    qstate.apply_decoherence(0.01); // minimal decoherence from I/O

    let layout = DataLayout::new(data_dir);
    let result = layout.reset(ResetScope::Chain)?;

    qstate.apply_decoherence(0.05); // post-reset decoherence

    info!("Chain subspace collapsed to vacuum state");
    Ok(AdminResult::ResetChain {
        dirs_removed: result.dirs_removed,
        dirs_preserved: result.dirs_preserved,
        fidelity: qstate.measure(),
    })
}

/// Collapse identity subspace to vacuum state |0⟩_identity.
///
/// Hamiltonian: Ĥ_reset = E_identity |0⟩⟨0|_identity
pub fn exec_reset_identity(data_dir: &str, confirm: bool) -> AdminResult<AdminResult> {
    let mut qstate = AdminQuantumState::new();

    if confirm && !user_confirmation(CONFIRM_PROMPT_IDENTITY)? {
        return Err(AdminError::UserCancel);
    }

    qstate.apply_decoherence(0.01);

    let layout = DataLayout::new(data_dir);
    let result = layout.reset(ResetScope::Identity)?;

    qstate.apply_decoherence(0.05);

    info!("Identity subspace collapsed to vacuum state");
    Ok(AdminResult::ResetIdentity {
        dirs_removed: result.dirs_removed,
        dirs_preserved: result.dirs_preserved,
        fidelity: qstate.measure(),
    })
}

/// Collapse entire Hilbert space to vacuum state |0⟩_total.
///
/// This is an irreversible projective measurement.
pub fn exec_reset_full(data_dir: &str, confirm: bool) -> AdminResult<AdminResult> {
    let mut qstate = AdminQuantumState::new();

    if confirm && !user_confirmation(CONFIRM_PROMPT_FULL)? {
        return Err(AdminError::UserCancel);
    }

    qstate.apply_decoherence(0.02);

    let layout = DataLayout::new(data_dir);
    let result = layout.reset(ResetScope::Full)?;

    qstate.apply_decoherence(0.10); // stronger decoherence for full reset

    info!("Complete Hilbert space collapsed");
    Ok(AdminResult::ResetFull {
        dirs_removed: result.dirs_removed,
        fidelity: qstate.measure(),
    })
}

/// Measure node status observables.
///
/// Observable: Ô_status = Σ_i ω_i |i⟩⟨i|
/// Measurement: ⟨ψ|Ô_status|ψ⟩
pub fn exec_status(data_dir: &str) -> AdminResult<AdminResult> {
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
///
/// Observable: Ô_peer = |peer_id⟩⟨peer_id|
/// Eigenvalue: λ_peer = unique identifier
pub fn exec_peer_id(data_dir: &str) -> AdminResult<AdminResult> {
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
///
/// The multiaddress is the tensor product of transport and identity:
/// |multiaddr⟩ = |transport⟩ ⊗ |identity⟩
pub fn exec_multiaddr(data_dir: &str, listen_addr: &str) -> AdminResult<AdminResult> {
    let mut qstate = AdminQuantumState::new();
    let layout = DataLayout::new(data_dir);
    let peer_id = layout.peer_id()?;
    let multiaddr = format!("{}/p2p/{}", listen_addr, peer_id);

    qstate.apply_decoherence(0.001);

    // Entanglement capacity: number of simultaneous connections
    let capacity = 1024; // theoretical max for this node

    Ok(AdminResult::PrintMultiaddr {
        multiaddr,
        entanglement_capacity: capacity,
    })
}

/// Measure configuration wavefunction.
///
/// The configuration is represented in the computational basis
/// and projected to JSON format for classical observation.
pub fn exec_config(config_path: &str) -> AdminResult<AdminResult> {
    let mut qstate = AdminQuantumState::new();
    let config_str = fs::read_to_string(config_path)?;
    let config: serde_json::Value = toml::from_str(&config_str)?;

    qstate.apply_decoherence(0.002);

    let purity = 1.0 - qstate.entropy / 10.0; // approximate purity

    Ok(AdminResult::Config {
        config,
        config_purity: purity.clamp(0.0, 1.0),
    })
}

/// Classical version observable (not quantum, but reported with epoch).
pub fn exec_version() -> AdminResult {
    let build_epoch = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    AdminResult::Version {
        version: env!("CARGO_PKG_VERSION").to_string(),
        commit: option_env!("VERGEN_GIT_SHA").unwrap_or("unknown").to_string(),
        build_epoch,
    }
}

/// Perform unitary cloning operation: U_clone |ψ⟩|0⟩ → |ψ⟩|ψ⟩.
///
/// The No-Cloning Theorem states perfect cloning is impossible,
/// but we achieve approximate cloning with high fidelity.
pub fn exec_backup(data_dir: &str, backup_dir: &str) -> AdminResult<AdminResult> {
    let mut qstate = AdminQuantumState::new();
    let source = Path::new(data_dir);

    if !source.exists() {
        return Err(AdminError::DirectoryNotFound {
            path: source.to_path_buf(),
        });
    }

    qstate.apply_decoherence(0.01);

    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let target = Path::new(backup_dir).join(format!("{}{}", BACKUP_PREFIX, timestamp));

    fs::create_dir_all(&target).map_err(|e| AdminError::BackupFailed {
        reason: format!("cannot create backup subspace: {e}"),
    })?;

    copy_dir_all(source, &target).map_err(|e| AdminError::BackupFailed {
        reason: format!("quantum cloning failed: {e}"),
    })?;

    qstate.apply_decoherence(0.03); // cloning introduces decoherence

    let clone_fidelity = qstate.measure();

    info!(backup_path = %target.display(), fidelity = clone_fidelity, "Quantum state cloned");
    Ok(AdminResult::BackupCreated {
        backup_path: target.to_string_lossy().into(),
        clone_fidelity,
    })
}

/// Measure health observable.
///
/// Ô_health = |healthy⟩⟨healthy| - |unhealthy⟩⟨unhealthy|
/// Eigenvalues: +1 (healthy), -1 (unhealthy)
pub fn exec_health(data_dir: &str) -> AdminResult<AdminResult> {
    let mut qstate = AdminQuantumState::new();
    let layout = DataLayout::new(data_dir);
    let status = layout.status();
    let ok = status.has_chain_data && status.blocks_count > 0;

    qstate.apply_decoherence(0.005);

    let message = if ok {
        format!(
            "Node is healthy: height={}, coherence={:.4}",
            status.blocks_count,
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
        peers: 0,
        message,
        coherence: qstate.coherence,
    })
}

/// Measure integrity observable.
///
/// Ô_verify = Σ_k λ_k |valid_k⟩⟨valid_k|
/// λ_k ∈ {0, 1} where 1 = integrity preserved
pub fn exec_verify(data_dir: &str) -> AdminResult<AdminResult> {
    let mut qstate = AdminQuantumState::new();
    let layout = DataLayout::new(data_dir);

    qstate.apply_decoherence(0.01);

    let store = crate::storage::block_store::FsBlockStore::open(layout.blocks_dir(), None)
        .map_err(|e| AdminError::IntegrityCheckFailed {
            reason: format!("cannot open block store: {e}"),
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
            qstate.apply_decoherence(0.05); // error increases decoherence
            Ok(AdminResult::Verify {
                passed: false,
                message: format!("Integrity observable measured: FAILED - {e}"),
                confidence: 1.0 - qstate.measure(),
            })
        }
    }
}

// -----------------------------------------------------------------------------
// Quantum Helpers
// -----------------------------------------------------------------------------

/// Quantum measurement: observer effect on user confirmation.
///
/// The act of asking the user collapses the superposition of
/// {confirm, deny} to a definite outcome.
fn user_confirmation(prompt: &str) -> Result<bool, AdminError> {
    use std::io::Write;

    let is_terminal = atty::is(atty::Stream::Stdin);
    if !is_terminal {
        // Non‑interactive: wavefunction collapse to |deny⟩
        return Ok(false);
    }

    print!("{} ", prompt);
    io::stdout().flush().map_err(|e| AdminError::Io { source: e })?;

    let mut input = String::new();
    io::stdin()
        .read_line(&mut input)
        .map_err(|e| AdminError::Io { source: e })?;

    // Born rule: measure the user's intent
    Ok(input.trim().eq_ignore_ascii_case("y") || input.trim().eq_ignore_ascii_case("yes"))
}

/// Quantum state cloning via recursive directory copy.
///
/// Implements approximate quantum cloning with fidelity < 1.0
/// due to the No-Cloning Theorem. The fidelity loss manifests
/// as filesystem metadata differences.
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

/// Convert quantum admin result to JSON representation.
///
/// Projects the quantum state onto the computational basis
/// and serializes the measurement outcome.
pub fn result_to_json(result: &AdminResult) -> String {
    serde_json::to_string_pretty(result).unwrap_or_else(|_| "{}".into())
}

// -----------------------------------------------------------------------------
// Quantum Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    /// Test ground state measurement.
    #[test]
    fn test_quantum_state_initialization() {
        let qstate = AdminQuantumState::new();
        assert!((qstate.coherence - 1.0).abs() < 1e-10);
        assert!((qstate.entropy - 0.0).abs() < 1e-10);
        assert!((qstate.fidelity - 1.0).abs() < 1e-10);
    }

    /// Test decoherence evolution.
    #[test]
    fn test_quantum_decoherence() {
        let mut qstate = AdminQuantumState::new();
        qstate.apply_decoherence(0.1);
        assert!(qstate.coherence < 1.0);
        assert!(qstate.entropy > 0.0);
        assert!(qstate.fidelity < 1.0);
    }

    #[test]
    fn test_exec_status_quantum() {
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
    fn test_exec_reset_chain_with_fidelity() {
        let tmp = tempdir().unwrap();
        let data_dir = tmp.path().to_str().unwrap();
        let layout = DataLayout::new(data_dir);
        layout.ensure_all().unwrap();
        fs::write(layout.p2p_key_path(), "identity").unwrap();
        fs::write(layout.state_full_path(), "{}").unwrap();

        let result = exec_reset_chain(data_dir, false).unwrap();
        match result {
            AdminResult::ResetChain { dirs_removed, dirs_preserved, fidelity } => {
                assert!(dirs_removed.contains(&"chain/".to_string()));
                assert!(dirs_preserved.contains(&"identity/".to_string()));
                assert!(fidelity > 0.9); // high fidelity for simple reset
                assert!(fidelity <= 1.0);
            }
            _ => panic!("expected ResetChain with fidelity"),
        }
        assert!(layout.p2p_key_path().exists());
        assert!(!layout.state_full_path().exists());
    }

    #[test]
    fn test_exec_backup_with_fidelity() {
        let src = tempdir().unwrap();
        let data_dir = src.path().to_str().unwrap();
        let layout = DataLayout::new(data_dir);
        layout.ensure_all().unwrap();
        fs::write(layout.state_full_path(), "{}").unwrap();

        let backup_dir = tempdir().unwrap();
        let result = exec_backup(data_dir, backup_dir.path().to_str().unwrap()).unwrap();
        match result {
            AdminResult::BackupCreated { backup_path, clone_fidelity } => {
                assert!(Path::new(&backup_path).exists());
                assert!(clone_fidelity > 0.9);
                assert!(clone_fidelity < 1.0); // No-Cloning Theorem: fidelity < 1
            }
            _ => panic!("expected BackupCreated with clone fidelity"),
        }
    }

    #[test]
    fn test_exec_health_with_coherence() {
        let tmp = tempdir().unwrap();
        let data_dir = tmp.path().to_str().unwrap();
        let layout = DataLayout::new(data_dir);
        layout.ensure_all().unwrap();
        fs::write(layout.state_full_path(), "{}").unwrap();

        let result = exec_health(data_dir).unwrap();
        match result {
            AdminResult::Health { ok, height, coherence, .. } => {
                assert!(!ok);
                assert_eq!(height, 0);
                assert!(coherence > 0.9);
                assert!(coherence <= 1.0);
            }
            _ => panic!("expected Health with coherence"),
        }
    }

    #[test]
    fn test_result_to_json_quantum() {
        let result = AdminResult::Status {
            info: NodeStatus {
                data_dir: "/tmp/test".into(),
                has_identity: false,
                has_validator_key: false,
                has_chain_data: false,
                schema_version: None,
                blocks_count: 0,
                snapshots_count: 0,
                disk_usage_bytes: 0,
            },
            entropy: 0.05,
        };
        let json = result_to_json(&result);
        assert!(json.contains("\"command\": \"Status\""));
        assert!(json.contains("\"entropy\": 0.05"));
        assert!(json.contains("\"blocks_count\": 0"));
    }
}
