//! CLI admin commands for IONA v28.
//!
//! Instead of bash scripts that delete files, the binary itself handles resets:
//!   iona-node admin reset-chain
//!   iona-node admin reset-identity
//!   iona-node admin status
//!
//! This ensures resets are compatible with the internal schema and layout.

use crate::storage::layout::{DataLayout, NodeStatus, ResetScope};
use serde::{Deserialize, Serialize};

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
}

/// Execute an admin command against the given data directory.
pub fn exec_reset_chain(data_dir: &str) -> Result<AdminResult, String> {
    let layout = DataLayout::new(data_dir);
    let result = layout
        .reset(ResetScope::Chain)
        .map_err(|e| format!("reset-chain failed: {e}"))?;
    Ok(AdminResult::ResetChain {
        dirs_removed: result.dirs_removed,
        dirs_preserved: result.dirs_preserved,
    })
}

pub fn exec_reset_identity(data_dir: &str) -> Result<AdminResult, String> {
    let layout = DataLayout::new(data_dir);
    let result = layout
        .reset(ResetScope::Identity)
        .map_err(|e| format!("reset-identity failed: {e}"))?;
    Ok(AdminResult::ResetIdentity {
        dirs_removed: result.dirs_removed,
        dirs_preserved: result.dirs_preserved,
    })
}

pub fn exec_reset_full(data_dir: &str) -> Result<AdminResult, String> {
    let layout = DataLayout::new(data_dir);
    let result = layout
        .reset(ResetScope::Full)
        .map_err(|e| format!("reset-full failed: {e}"))?;
    Ok(AdminResult::ResetFull {
        dirs_removed: result.dirs_removed,
    })
}

pub fn exec_status(data_dir: &str) -> Result<AdminResult, String> {
    let layout = DataLayout::new(data_dir);
    let status = layout.status();
    Ok(AdminResult::Status { info: status })
}

/// Print the node's peer ID derived from its identity key.
pub fn exec_print_peer_id(data_dir: &str, seed: u64) -> Result<AdminResult, String> {
    // Derive the peer ID from the seed (same as how the node generates it).
    let mut seed32 = [0u8; 32];
    seed32[..8].copy_from_slice(&seed.to_le_bytes());
    let peer_id = format!("iona-peer-{}", hex::encode(&seed32[..8]));
    Ok(AdminResult::PrintPeerId { peer_id })
}

/// Format the result as JSON for scripting.
pub fn result_to_json(result: &AdminResult) -> String {
    serde_json::to_string_pretty(result).unwrap_or_else(|_| "{}".into())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_exec_status() {
        let tmp = tempfile::tempdir().unwrap();
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
        let tmp = tempfile::tempdir().unwrap();
        let data_dir = tmp.path().to_str().unwrap();

        // Create layout first.
        let layout = DataLayout::new(data_dir);
        layout.ensure_all().unwrap();
        std::fs::write(layout.p2p_key_path(), "identity").unwrap();
        std::fs::write(layout.state_full_path(), "{}").unwrap();

        let result = exec_reset_chain(data_dir).unwrap();
        match result {
            AdminResult::ResetChain {
                dirs_removed,
                dirs_preserved,
            } => {
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
    fn test_exec_reset_identity() {
        let tmp = tempfile::tempdir().unwrap();
        let data_dir = tmp.path().to_str().unwrap();

        let layout = DataLayout::new(data_dir);
        layout.ensure_all().unwrap();
        std::fs::write(layout.p2p_key_path(), "identity").unwrap();
        std::fs::write(layout.state_full_path(), "{}").unwrap();

        let result = exec_reset_identity(data_dir).unwrap();
        match result {
            AdminResult::ResetIdentity {
                dirs_removed,
                dirs_preserved,
            } => {
                assert!(dirs_removed.contains(&"identity/".to_string()));
                assert!(dirs_preserved.contains(&"chain/".to_string()));
            }
            _ => panic!("expected ResetIdentity result"),
        }

        // Identity gone.
        assert!(!layout.p2p_key_path().exists());
        // Chain preserved.
        assert!(layout.state_full_path().exists());
    }

    #[test]
    fn test_exec_reset_full() {
        let tmp = tempfile::tempdir().unwrap();
        let data_dir = tmp.path().to_str().unwrap();

        let layout = DataLayout::new(data_dir);
        layout.ensure_all().unwrap();
        std::fs::write(layout.p2p_key_path(), "identity").unwrap();
        std::fs::write(layout.state_full_path(), "{}").unwrap();

        let result = exec_reset_full(data_dir).unwrap();
        match result {
            AdminResult::ResetFull { dirs_removed } => {
                assert!(!dirs_removed.is_empty());
            }
            _ => panic!("expected ResetFull result"),
        }

        // Everything gone (dirs recreated empty).
        assert!(!layout.p2p_key_path().exists());
        assert!(!layout.state_full_path().exists());
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

    #[test]
    fn test_print_peer_id() {
        let result = exec_print_peer_id("/tmp", 42).unwrap();
        match result {
            AdminResult::PrintPeerId { peer_id } => {
                assert!(peer_id.starts_with("iona-peer-"));
            }
            _ => panic!("expected PrintPeerId"),
        }
    }
}
