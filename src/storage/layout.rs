//! Standard data directory layout for IONA v28.
//!
//! ```text
//! <data_dir>/
//!   identity/
//!     p2p_key.json        # libp2p keypair (node identity on the network)
//!     node_meta.json      # schema_version, protocol_version, node_version
//!   validator/
//!     validator_key.json   # ed25519 signing key (only if this node is a validator)
//!   chain/
//!     blocks/              # committed blocks (one JSON per height)
//!     wal/                 # write-ahead log segments
//!     state/               # state_full.json, stakes.json, evidence
//!     receipts/            # transaction receipts
//!     snapshots/           # periodic state snapshots
//!   peerstore/
//!     peers.json           # known peers with last-seen timestamps
//!     quarantine.json      # quarantined peers
//! ```
//!
//! Benefits:
//!   - `reset chain` only deletes `chain/` — identity preserved
//!   - `reset identity` only deletes `identity/` — chain data untouched
//!   - `peerstore/` survives both resets

use serde::{Deserialize, Serialize};
use std::{fs, io, path::{Path, PathBuf}};

/// Standard directory layout.
#[derive(Clone, Debug)]
pub struct DataLayout {
    pub root: PathBuf,
}

impl DataLayout {
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self { root: root.into() }
    }

    // ── Sub-directories ──────────────────────────────────────────────────

    pub fn identity_dir(&self) -> PathBuf { self.root.join("identity") }
    pub fn validator_dir(&self) -> PathBuf { self.root.join("validator") }
    pub fn chain_dir(&self) -> PathBuf { self.root.join("chain") }
    pub fn peerstore_dir(&self) -> PathBuf { self.root.join("peerstore") }

    // ── Chain sub-dirs ───────────────────────────────────────────────────

    pub fn blocks_dir(&self) -> PathBuf { self.chain_dir().join("blocks") }
    pub fn wal_dir(&self) -> PathBuf { self.chain_dir().join("wal") }
    pub fn state_dir(&self) -> PathBuf { self.chain_dir().join("state") }
    pub fn receipts_dir(&self) -> PathBuf { self.chain_dir().join("receipts") }
    pub fn snapshots_dir(&self) -> PathBuf { self.chain_dir().join("snapshots") }

    // ── Identity files ───────────────────────────────────────────────────

    pub fn p2p_key_path(&self) -> PathBuf { self.identity_dir().join("p2p_key.json") }
    pub fn node_meta_path(&self) -> PathBuf { self.identity_dir().join("node_meta.json") }

    // ── Validator files ──────────────────────────────────────────────────

    pub fn validator_key_path(&self) -> PathBuf { self.validator_dir().join("validator_key.json") }
    pub fn validator_key_enc_path(&self) -> PathBuf { self.validator_dir().join("validator_key.enc") }

    // ── Chain state files ────────────────────────────────────────────────

    pub fn state_full_path(&self) -> PathBuf { self.state_dir().join("state_full.json") }
    pub fn stakes_path(&self) -> PathBuf { self.state_dir().join("stakes.json") }
    pub fn evidence_path(&self) -> PathBuf { self.state_dir().join("evidence.jsonl") }
    pub fn schema_path(&self) -> PathBuf { self.state_dir().join("schema.json") }
    pub fn tx_index_path(&self) -> PathBuf { self.state_dir().join("tx_index.json") }

    // ── Peerstore files ──────────────────────────────────────────────────

    pub fn peers_path(&self) -> PathBuf { self.peerstore_dir().join("peers.json") }
    pub fn quarantine_path(&self) -> PathBuf { self.peerstore_dir().join("quarantine.json") }

    // ── Ensure all directories exist ─────────────────────────────────────

    pub fn ensure_all(&self) -> io::Result<()> {
        for dir in &[
            self.identity_dir(),
            self.validator_dir(),
            self.blocks_dir(),
            self.wal_dir(),
            self.state_dir(),
            self.receipts_dir(),
            self.snapshots_dir(),
            self.peerstore_dir(),
        ] {
            fs::create_dir_all(dir)?;
        }
        Ok(())
    }

    /// Check if this is a fresh (empty) data directory.
    pub fn is_fresh(&self) -> bool {
        !self.state_full_path().exists() && !self.validator_key_path().exists()
    }

    /// Check if chain data exists (actual files, not just empty dirs).
    pub fn has_chain_data(&self) -> bool {
        self.state_full_path().exists()
            || self.blocks_dir().read_dir().map(|mut rd| rd.next().is_some()).unwrap_or(false)
    }

    /// Check if identity exists.
    pub fn has_identity(&self) -> bool {
        self.p2p_key_path().exists()
    }

    /// Check if validator key exists.
    pub fn has_validator_key(&self) -> bool {
        self.validator_key_path().exists() || self.validator_key_enc_path().exists()
    }
}

// ── Reset operations ─────────────────────────────────────────────────────

/// What to reset.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResetScope {
    /// Delete chain/ only — preserves identity and peerstore.
    Chain,
    /// Delete identity/ only — preserves chain data and peerstore.
    Identity,
    /// Delete everything (chain + identity + peerstore).
    Full,
}

/// Result of a reset operation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResetResult {
    pub scope: String,
    pub dirs_removed: Vec<String>,
    pub dirs_preserved: Vec<String>,
}

impl DataLayout {
    /// Perform a controlled reset.
    ///
    /// Returns what was removed and what was preserved.
    pub fn reset(&self, scope: ResetScope) -> io::Result<ResetResult> {
        let mut removed = Vec::new();
        let mut preserved = Vec::new();

        match scope {
            ResetScope::Chain => {
                if self.chain_dir().exists() {
                    fs::remove_dir_all(self.chain_dir())?;
                    removed.push("chain/".into());
                }
                preserved.push("identity/".into());
                preserved.push("validator/".into());
                preserved.push("peerstore/".into());
            }
            ResetScope::Identity => {
                if self.identity_dir().exists() {
                    fs::remove_dir_all(self.identity_dir())?;
                    removed.push("identity/".into());
                }
                preserved.push("validator/".into());
                preserved.push("chain/".into());
                preserved.push("peerstore/".into());
            }
            ResetScope::Full => {
                for dir in &["identity", "validator", "chain", "peerstore"] {
                    let p = self.root.join(dir);
                    if p.exists() {
                        fs::remove_dir_all(&p)?;
                        removed.push(format!("{dir}/"));
                    }
                }
            }
        }

        // Re-create directory structure.
        self.ensure_all()?;

        Ok(ResetResult {
            scope: format!("{:?}", scope),
            dirs_removed: removed,
            dirs_preserved: preserved,
        })
    }
}

// ── Node status (for CLI `admin status`) ─────────────────────────────────

/// Summary of node status from on-disk data.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeStatus {
    pub data_dir: String,
    pub has_identity: bool,
    pub has_validator_key: bool,
    pub has_chain_data: bool,
    pub schema_version: Option<u32>,
    pub blocks_count: usize,
    pub snapshots_count: usize,
    pub disk_usage_bytes: u64,
}

impl DataLayout {
    /// Gather node status from on-disk data (no RPC needed).
    pub fn status(&self) -> NodeStatus {
        let blocks_count = self.blocks_dir()
            .read_dir()
            .map(|rd| rd.filter_map(|e| e.ok()).count())
            .unwrap_or(0);

        let snapshots_count = self.snapshots_dir()
            .read_dir()
            .map(|rd| rd.filter_map(|e| e.ok()).count())
            .unwrap_or(0);

        let schema_version = fs::read_to_string(self.schema_path())
            .ok()
            .and_then(|s| serde_json::from_str::<serde_json::Value>(&s).ok())
            .and_then(|v| v.get("version")?.as_u64())
            .map(|v| v as u32);

        let disk_usage = dir_size(&self.root);

        NodeStatus {
            data_dir: self.root.display().to_string(),
            has_identity: self.has_identity(),
            has_validator_key: self.has_validator_key(),
            has_chain_data: self.has_chain_data(),
            schema_version,
            blocks_count,
            snapshots_count,
            disk_usage_bytes: disk_usage,
        }
    }
}

/// Recursively compute directory size in bytes.
fn dir_size(path: &Path) -> u64 {
    if !path.exists() { return 0; }
    let mut total = 0u64;
    if let Ok(rd) = fs::read_dir(path) {
        for entry in rd.filter_map(|e| e.ok()) {
            let p = entry.path();
            if p.is_file() {
                total += entry.metadata().map(|m| m.len()).unwrap_or(0);
            } else if p.is_dir() {
                total += dir_size(&p);
            }
        }
    }
    total
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_layout_paths() {
        let layout = DataLayout::new("/var/lib/iona/val2");
        assert_eq!(layout.identity_dir(), PathBuf::from("/var/lib/iona/val2/identity"));
        assert_eq!(layout.validator_dir(), PathBuf::from("/var/lib/iona/val2/validator"));
        assert_eq!(layout.chain_dir(), PathBuf::from("/var/lib/iona/val2/chain"));
        assert_eq!(layout.peerstore_dir(), PathBuf::from("/var/lib/iona/val2/peerstore"));
        assert_eq!(layout.blocks_dir(), PathBuf::from("/var/lib/iona/val2/chain/blocks"));
        assert_eq!(layout.wal_dir(), PathBuf::from("/var/lib/iona/val2/chain/wal"));
        assert_eq!(layout.state_full_path(), PathBuf::from("/var/lib/iona/val2/chain/state/state_full.json"));
        assert_eq!(layout.validator_key_path(), PathBuf::from("/var/lib/iona/val2/validator/validator_key.json"));
        assert_eq!(layout.p2p_key_path(), PathBuf::from("/var/lib/iona/val2/identity/p2p_key.json"));
        assert_eq!(layout.peers_path(), PathBuf::from("/var/lib/iona/val2/peerstore/peers.json"));
    }

    #[test]
    fn test_fresh_layout() {
        let tmp = tempfile::tempdir().unwrap();
        let layout = DataLayout::new(tmp.path());
        assert!(layout.is_fresh());
        assert!(!layout.has_chain_data());
        assert!(!layout.has_identity());
        assert!(!layout.has_validator_key());
    }

    #[test]
    fn test_ensure_all() {
        let tmp = tempfile::tempdir().unwrap();
        let layout = DataLayout::new(tmp.path());
        layout.ensure_all().unwrap();
        assert!(layout.identity_dir().exists());
        assert!(layout.validator_dir().exists());
        assert!(layout.blocks_dir().exists());
        assert!(layout.wal_dir().exists());
        assert!(layout.state_dir().exists());
        assert!(layout.receipts_dir().exists());
        assert!(layout.snapshots_dir().exists());
        assert!(layout.peerstore_dir().exists());
    }

    #[test]
    fn test_reset_chain_only() {
        let tmp = tempfile::tempdir().unwrap();
        let layout = DataLayout::new(tmp.path());
        layout.ensure_all().unwrap();

        // Create some files
        fs::write(layout.p2p_key_path(), "identity").unwrap();
        fs::write(layout.state_full_path(), "{}").unwrap();
        fs::write(layout.peers_path(), "{}").unwrap();

        let result = layout.reset(ResetScope::Chain).unwrap();
        assert!(result.dirs_removed.contains(&"chain/".to_string()));
        assert!(result.dirs_preserved.contains(&"identity/".to_string()));

        // Identity preserved
        assert!(layout.p2p_key_path().exists());
        // Chain data gone (but dirs re-created empty)
        assert!(!layout.state_full_path().exists());
        // Peerstore preserved
        assert!(layout.peers_path().exists());
    }

    #[test]
    fn test_reset_identity_only() {
        let tmp = tempfile::tempdir().unwrap();
        let layout = DataLayout::new(tmp.path());
        layout.ensure_all().unwrap();

        fs::write(layout.p2p_key_path(), "identity").unwrap();
        fs::write(layout.state_full_path(), "{}").unwrap();

        let result = layout.reset(ResetScope::Identity).unwrap();
        assert!(result.dirs_removed.contains(&"identity/".to_string()));
        assert!(result.dirs_preserved.contains(&"chain/".to_string()));

        // Identity gone
        assert!(!layout.p2p_key_path().exists());
        // Chain preserved
        assert!(layout.state_full_path().exists());
    }

    #[test]
    fn test_reset_full() {
        let tmp = tempfile::tempdir().unwrap();
        let layout = DataLayout::new(tmp.path());
        layout.ensure_all().unwrap();

        fs::write(layout.p2p_key_path(), "identity").unwrap();
        fs::write(layout.state_full_path(), "{}").unwrap();
        fs::write(layout.peers_path(), "{}").unwrap();

        let result = layout.reset(ResetScope::Full).unwrap();
        assert!(!result.dirs_removed.is_empty());

        // Everything gone (but dirs re-created empty)
        assert!(!layout.p2p_key_path().exists());
        assert!(!layout.state_full_path().exists());
        assert!(!layout.peers_path().exists());
    }

    #[test]
    fn test_status() {
        let tmp = tempfile::tempdir().unwrap();
        let layout = DataLayout::new(tmp.path());
        layout.ensure_all().unwrap();

        let status = layout.status();
        assert_eq!(status.blocks_count, 0);
        assert_eq!(status.snapshots_count, 0);
        assert!(!status.has_identity);
        assert!(!status.has_validator_key);
        assert!(!status.has_chain_data);
        assert!(status.schema_version.is_none());
    }
}
