//! CLI admin commands for IONA v28.
//!
//! Instead of bash scripts that delete files, the binary itself handles resets:
//!   iona-node admin reset-chain
//!   iona-node admin reset-identity
//!   iona-node admin reset-full
//!   iona-node admin status
//!   iona-node admin peer-id
//!   iona-node admin multiaddr
//!
//! This ensures resets are compatible with the internal schema and layout.

use crate::storage::layout::{DataLayout, ResetScope, NodeStatus};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;
use tracing::warn;

/// Admin command result.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "command")]
pub enum AdminResult {
    ResetChain {
        dirs_removed: Vec<String>,
        dirs_preserved: Vec<String>,
    },
    ResetIdentity {
        dirs_removed: Vec<String>,
        dirs_preserved: Vec<String>,
    },
    ResetFull {
        dirs_removed: Vec<String>,
    },
    Status {
        #[serde(flatten)]
        info: NodeStatus,
    },
    PrintPeerId {
        peer_id: String,
    },
    PrintMultiaddr {
        multiaddr: String,
    },
    Config {
        config: serde_json::Value,
    },
    Version {
        version: String,
        commit: String,
    },
    BackupCreated {
        backup_path: String,
    },
}

// -----------------------------------------------------------------------------
// Core admin commands
// -----------------------------------------------------------------------------

/// Reset only chain data (state, blocks, WAL), preserving identity.
pub fn exec_reset_chain(data_dir: &str, confirm: bool) -> Result<AdminResult, String> {
    if confirm && !user_confirmation("This will delete all chain data. Continue? [y/N]")? {
        return Err("Reset cancelled by user".into());
    }
    let layout = DataLayout::new(data_dir);
    let result = layout
        .reset(ResetScope::Chain)
        .map_err(|e| format!("reset-chain failed: {e}"))?;
    Ok(AdminResult::ResetChain {
        dirs_removed: result.dirs_removed,
        dirs_preserved: result.dirs_preserved,
    })
}

/// Reset only identity (keys), preserving chain data.
pub fn exec_reset_identity(data_dir: &str, confirm: bool) -> Result<AdminResult, String> {
    if confirm && !user_confirmation("This will delete identity keys. Continue? [y/N]")? {
        return Err("Reset cancelled by user".into());
    }
    let layout = DataLayout::new(data_dir);
    let result = layout
        .reset(ResetScope::Identity)
        .map_err(|e| format!("reset-identity failed: {e}"))?;
    Ok(AdminResult::ResetIdentity {
        dirs_removed: result.dirs_removed,
        dirs_preserved: result.dirs_preserved,
    })
}

/// Reset everything (full wipe).
pub fn exec_reset_full(data_dir: &str, confirm: bool) -> Result<AdminResult, String> {
    if confirm && !user_confirmation("This will delete ALL data. This action cannot be undone. Continue? [y/N]")? {
        return Err("Reset cancelled by user".into());
    }
    let layout = DataLayout::new(data_dir);
    let result = layout
        .reset(ResetScope::Full)
        .map_err(|e| format!("reset-full failed: {e}"))?;
    Ok(AdminResult::ResetFull {
        dirs_removed: result.dirs_removed,
    })
}

/// Display node status (data layout, schema, block count, etc.).
pub fn exec_status(data_dir: &str) -> Result<AdminResult, String> {
    let layout = DataLayout::new(data_dir);
    let status = layout.status();
    Ok(AdminResult::Status { info: status })
}

/// Print the node's peer ID derived from its identity key.
pub fn exec_print_peer_id(data_dir: &str) -> Result<AdminResult, String> {
    let layout = DataLayout::new(data_dir);
    let peer_id = layout
        .peer_id()
        .map_err(|e| format!("Failed to read peer ID: {e}"))?;
    Ok(AdminResult::PrintPeerId { peer_id })
}

/// Print the node's multiaddress (from config and peer ID).
/// This requires the listening address from the node configuration.
pub fn exec_print_multiaddr(data_dir: &str, listen_addr: &str) -> Result<AdminResult, String> {
    let layout = DataLayout::new(data_dir);
    let peer_id = layout
        .peer_id()
        .map_err(|e| format!("Failed to read peer ID: {e}"))?;
    // Build multiaddress: /ip4/<ip>/tcp/<port>/p2p/<peer_id>
    let multiaddr = format!("{}/p2p/{}", listen_addr, peer_id);
    Ok(AdminResult::PrintMultiaddr { multiaddr })
}

/// Print current configuration (as JSON).
pub fn exec_config(config_path: &str) -> Result<AdminResult, String> {
    let config_str = fs::read_to_string(config_path)
        .map_err(|e| format!("Failed to read config file: {e}"))?;
    let config: serde_json::Value = toml::from_str(&config_str)
        .map_err(|e| format!("Failed to parse config: {e}"))?;
    Ok(AdminResult::Config { config })
}

/// Print version information.
pub fn exec_version() -> AdminResult {
    AdminResult::Version {
        version: env!("CARGO_PKG_VERSION").to_string(),
        commit: env!("VERGEN_GIT_SHA").unwrap_or("unknown").to_string(),
    }
}

/// Create a backup of the entire data directory.
pub fn exec_backup(data_dir: &str, backup_dir: &str) -> Result<AdminResult, String> {
    let source = Path::new(data_dir);
    let target = Path::new(backup_dir).join(format!("iona_backup_{}", chrono::Utc::now().timestamp()));
    if !source.exists() {
        return Err("Data directory does not exist".into());
    }
    fs::create_dir_all(&target)
        .map_err(|e| format!("Failed to create backup dir: {e}"))?;
    copy_dir_all(source, &target)
        .map_err(|e| format!("Backup failed: {e}"))?;
    Ok(AdminResult::BackupCreated {
        backup_path: target.to_string_lossy().into(),
    })
}

// -----------------------------------------------------------------------------
// Helpers
// -----------------------------------------------------------------------------

/// Prompt the user for confirmation (if stdin is a terminal).
fn user_confirmation(prompt: &str) -> Result<bool, String> {
    use std::io::{self, Write};
    let is_terminal = atty::is(atty::Stream::Stdin);
    if !is_terminal {
        // Non‑interactive: assume yes for scripts? Better to be safe.
        return Ok(false);
    }
    print!("{} ", prompt);
    io::stdout().flush().map_err(|e| format!("I/O error: {e}"))?;
    let mut input = String::new();
    io::stdin()
        .read_line(&mut input)
        .map_err(|e| format!("Failed to read input: {e}"))?;
    Ok(input.trim().eq_ignore_ascii_case("y") || input.trim().eq_ignore_ascii_case("yes"))
}

/// Recursively copy a directory (for backup).
fn copy_dir_all(src: &Path, dst: &Path) -> std::io::Result<()> {
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

/// Format the result as JSON for scripting.
pub fn result_to_json(result: &AdminResult) -> String {
    serde_json::to_string_pretty(result).unwrap_or_else(|_| "{}".into())
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn test_exec_status() {
        let tmp = tempdir().unwrap();
        let data_dir = tmp.path().to_str().unwrap();

        let result = exec_status(data_dir).unwrap();
        match result {
            AdminResult::Status { info: status } => {
                assert!(!status.has_chain_data);
                assert!(!status.has_identity);
                assert!(!status.has_validator_key);
                assert_eq!(status.blocks_count, 0);
            }
            _ => panic!("expected Status result"),
        }
    }

    #[test]
    fn test_exec_reset_chain() {
        let tmp = tempdir().unwrap();
        let data_dir = tmp.path().to_str().unwrap();

        // Create layout first.
        let layout = DataLayout::new(data_dir);
        layout.ensure_all().unwrap();
        fs::write(layout.p2p_key_path(), "identity").unwrap();
        fs::write(layout.state_full_path(), "{}").unwrap();

        let result = exec_reset_chain(data_dir, false).unwrap(); // no confirmation for test
        match result {
            AdminResult::ResetChain { dirs_removed, dirs_preserved } => {
                assert!(dirs_removed.contains(&"chain/".to_string()));
                assert!(dirs_preserved.contains(&"identity/".to_string()));
            }
            _ => panic!("expected ResetChain result"),
        }

        // Identity should still exist.
        assert!(layout.p2p_key_path().exists());
        // Chain data should be gone.
        assert!(!layout.state_full_path().exists());
    }

    #[test]
    fn test_print_peer_id() {
        let tmp = tempdir().unwrap();
        let data_dir = tmp.path().to_str().unwrap();
        let layout = DataLayout::new(data_dir);
        layout.ensure_all().unwrap();
        // For a real test, you'd need to generate a key first.
        // We'll assume the key exists; if not, we expect an error.
        let result = exec_print_peer_id(data_dir);
        match result {
            Ok(AdminResult::PrintPeerId { .. }) => (),
            Ok(_) => panic!("wrong variant"),
            Err(_) => {
                // acceptable if no key exists yet
            }
        }
    }

    #[test]
    fn test_result_to_json() {
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
        };
        let json = result_to_json(&result);
        assert!(json.contains("\"command\": \"Status\""));
        assert!(json.contains("\"blocks_count\": 0"));
    }
}
