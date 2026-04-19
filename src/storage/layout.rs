//! Standard data directory layout for IONA v28.
//!
//! This module defines the on‑disk directory structure and provides helpers
//! for accessing key files, resetting parts of the state, and retrieving
//! node status.
//!
//! # Directory Layout
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
//! # Reset Operations
//!
//! - `reset chain` only deletes `chain/` — identity preserved
//! - `reset identity` only deletes `identity/` — chain data untouched
//! - `reset full` deletes everything
//!
//! # Example
//!
//! ```
//! use iona::storage::layout::DataLayout;
//!
//! let layout = DataLayout::new("./data/node");
//! layout.ensure_all().unwrap();
//! let peer_id = layout.peer_id().unwrap();
//! ```

use crate::crypto::ed25519::{Ed25519Keypair, Ed25519Signer};
use crate::crypto::PublicKeyBytes;
use serde::{Deserialize, Serialize};
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use tracing::{debug, info, warn};

// -----------------------------------------------------------------------------
// DataLayout
// -----------------------------------------------------------------------------

/// Standard directory layout for node data.
#[derive(Clone, Debug)]
pub struct DataLayout {
    pub root: PathBuf,
}

impl DataLayout {
    /// Create a new layout rooted at the given path.
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self { root: root.into() }
    }

    // -------------------------------------------------------------------------
    // Directory accessors
    // -------------------------------------------------------------------------

    /// Directory for node identity (P2P key, node metadata).
    #[must_use]
    pub fn identity_dir(&self) -> PathBuf {
        self.root.join("identity")
    }

    /// Directory for validator signing key (if any).
    #[must_use]
    pub fn validator_dir(&self) -> PathBuf {
        self.root.join("validator")
    }

    /// Directory for chain data (blocks, WAL, state, receipts, snapshots).
    #[must_use]
    pub fn chain_dir(&self) -> PathBuf {
        self.root.join("chain")
    }

    /// Directory for peer store (known peers, quarantine).
    #[must_use]
    pub fn peerstore_dir(&self) -> PathBuf {
        self.root.join("peerstore")
    }

    // -------------------------------------------------------------------------
    // Chain sub‑directories
    // -------------------------------------------------------------------------

    /// Directory for committed blocks.
    #[must_use]
    pub fn blocks_dir(&self) -> PathBuf {
        self.chain_dir().join("blocks")
    }

    /// Directory for write‑ahead log segments.
    #[must_use]
    pub fn wal_dir(&self) -> PathBuf {
        self.chain_dir().join("wal")
    }

    /// Directory for state files.
    #[must_use]
    pub fn state_dir(&self) -> PathBuf {
        self.chain_dir().join("state")
    }

    /// Directory for transaction receipts.
    #[must_use]
    pub fn receipts_dir(&self) -> PathBuf {
        self.chain_dir().join("receipts")
    }

    /// Directory for snapshots.
    #[must_use]
    pub fn snapshots_dir(&self) -> PathBuf {
        self.chain_dir().join("snapshots")
    }

    // -------------------------------------------------------------------------
    // Identity files
    // -------------------------------------------------------------------------

    /// Path to the P2P key file (JSON).
    #[must_use]
    pub fn p2p_key_path(&self) -> PathBuf {
        self.identity_dir().join("p2p_key.json")
    }

    /// Path to the node metadata file.
    #[must_use]
    pub fn node_meta_path(&self) -> PathBuf {
        self.identity_dir().join("node_meta.json")
    }

    // -------------------------------------------------------------------------
    // Validator files
    // -------------------------------------------------------------------------

    /// Path to the plaintext validator key file (JSON).
    #[must_use]
    pub fn validator_key_path(&self) -> PathBuf {
        self.validator_dir().join("validator_key.json")
    }

    /// Path to the encrypted validator key file.
    #[must_use]
    pub fn validator_key_enc_path(&self) -> PathBuf {
        self.validator_dir().join("validator_key.enc")
    }

    // -------------------------------------------------------------------------
    // Chain state files
    // -------------------------------------------------------------------------

    /// Path to the full state JSON file.
    #[must_use]
    pub fn state_full_path(&self) -> PathBuf {
        self.state_dir().join("state_full.json")
    }

    /// Path to the stakes file.
    #[must_use]
    pub fn stakes_path(&self) -> PathBuf {
        self.state_dir().join("stakes.json")
    }

    /// Path to the evidence store (JSONL).
    #[must_use]
    pub fn evidence_path(&self) -> PathBuf {
        self.state_dir().join("evidence.jsonl")
    }

    /// Path to the schema metadata file.
    #[must_use]
    pub fn schema_path(&self) -> PathBuf {
        self.state_dir().join("schema.json")
    }

    /// Path to the transaction index file.
    #[must_use]
    pub fn tx_index_path(&self) -> PathBuf {
        self.state_dir().join("tx_index.json")
    }

    // -------------------------------------------------------------------------
    // Peerstore files
    // -------------------------------------------------------------------------

    /// Path to the known peers file.
    #[must_use]
    pub fn peers_path(&self) -> PathBuf {
        self.peerstore_dir().join("peers.json")
    }

    /// Path to the quarantine list file.
    #[must_use]
    pub fn quarantine_path(&self) -> PathBuf {
        self.peerstore_dir().join("quarantine.json")
    }

    // -------------------------------------------------------------------------
    // Directory creation and checks
    // -------------------------------------------------------------------------

    /// Ensure all required directories exist.
    pub fn ensure_all(&self) -> io::Result<()> {
        let dirs = [
            self.identity_dir(),
            self.validator_dir(),
            self.blocks_dir(),
            self.wal_dir(),
            self.state_dir(),
            self.receipts_dir(),
            self.snapshots_dir(),
            self.peerstore_dir(),
        ];
        for dir in dirs {
            fs::create_dir_all(&dir)?;
            debug!(path = %dir.display(), "ensured directory");
        }
        Ok(())
    }

    /// Check if this is a fresh (empty) data directory.
    #[must_use]
    pub fn is_fresh(&self) -> bool {
        !self.state_full_path().exists() && !self.validator_key_path().exists()
    }

    /// Check if chain data exists (actual files, not just empty dirs).
    #[must_use]
    pub fn has_chain_data(&self) -> bool {
        self.state_full_path().exists()
            || self
                .blocks_dir()
                .read_dir()
                .map(|mut rd| rd.next().is_some())
                .unwrap_or(false)
    }

    /// Check if identity exists.
    #[must_use]
    pub fn has_identity(&self) -> bool {
        self.p2p_key_path().exists()
    }

    /// Check if validator key exists.
    #[must_use]
    pub fn has_validator_key(&self) -> bool {
        self.validator_key_path().exists() || self.validator_key_enc_path().exists()
    }

    // -------------------------------------------------------------------------
    // Key management
    // -------------------------------------------------------------------------

    /// Load the P2P keypair (libp2p) as an Ed25519 keypair.
    ///
    /// The key is stored as a JSON file with a 32‑byte seed.
    pub fn load_p2p_keypair(&self) -> io::Result<Ed25519Keypair> {
        let path = self.p2p_key_path();
        let content = fs::read_to_string(&path)?;
        let seed_hex: String = serde_json::from_str(&content)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
        let seed = hex::decode(seed_hex)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
        if seed.len() != 32 {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "seed must be 32 bytes"));
        }
        let mut seed_arr = [0u8; 32];
        seed_arr.copy_from_slice(&seed);
        Ok(Ed25519Keypair::from_seed(seed_arr))
    }

    /// Save the P2P keypair (libp2p) as an Ed25519 keypair.
    pub fn save_p2p_keypair(&self, keypair: &Ed25519Keypair) -> io::Result<()> {
        let path = self.p2p_key_path();
        let seed = keypair.to_seed();
        let seed_hex = hex::encode(seed);
        let json = serde_json::to_string_pretty(&seed_hex)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
        fs::write(&path, json)?;
        debug!(path = %path.display(), "saved P2P keypair");
        Ok(())
    }

    /// Generate a new random P2P keypair and save it.
    pub fn generate_p2p_keypair(&self) -> io::Result<Ed25519Keypair> {
        let keypair = Ed25519Keypair::random();
        self.save_p2p_keypair(&keypair)?;
        Ok(keypair)
    }

    /// Load the validator keypair (Ed25519) from the plaintext file.
    pub fn load_validator_keypair(&self) -> io::Result<Ed25519Keypair> {
        let path = self.validator_key_path();
        let content = fs::read_to_string(&path)?;
        let seed_hex: String = serde_json::from_str(&content)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
        let seed = hex::decode(seed_hex)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
        if seed.len() != 32 {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "seed must be 32 bytes"));
        }
        let mut seed_arr = [0u8; 32];
        seed_arr.copy_from_slice(&seed);
        Ok(Ed25519Keypair::from_seed(seed_arr))
    }

    /// Save the validator keypair to the plaintext file.
    pub fn save_validator_keypair(&self, keypair: &Ed25519Keypair) -> io::Result<()> {
        let path = self.validator_key_path();
        let seed = keypair.to_seed();
        let seed_hex = hex::encode(seed);
        let json = serde_json::to_string_pretty(&seed_hex)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
        fs::write(&path, json)?;
        debug!(path = %path.display(), "saved validator keypair");
        Ok(())
    }

    /// Generate a new random validator keypair and save it.
    pub fn generate_validator_keypair(&self) -> io::Result<Ed25519Keypair> {
        let keypair = Ed25519Keypair::random();
        self.save_validator_keypair(&keypair)?;
        Ok(keypair)
    }

    /// Get the peer ID (libp2p) from the P2P key.
    pub fn peer_id(&self) -> io::Result<String> {
        let keypair = self.load_p2p_keypair()?;
        let public_key = keypair.public_key();
        // Derive peer ID as blake3 of the public key (first 16 bytes hex).
        let hash = blake3::hash(&public_key.0);
        Ok(hex::encode(&hash.as_bytes()[..16]))
    }

    /// Create an Ed25519 signer from the validator key.
    pub fn validator_signer(&self) -> io::Result<Ed25519Signer> {
        let keypair = self.load_validator_keypair()?;
        Ok(Ed25519Signer::from_keypair(keypair))
    }

    // -------------------------------------------------------------------------
    // Reset operations
    // -------------------------------------------------------------------------

    /// Perform a controlled reset of the data directory.
    pub fn reset(&self, scope: ResetScope) -> io::Result<ResetResult> {
        let mut removed = Vec::new();
        let mut preserved = Vec::new();

        match scope {
            ResetScope::Chain => {
                if self.chain_dir().exists() {
                    fs::remove_dir_all(self.chain_dir())?;
                    removed.push("chain/".into());
                    info!("reset: removed chain/");
                }
                preserved.push("identity/".into());
                preserved.push("validator/".into());
                preserved.push("peerstore/".into());
            }
            ResetScope::Identity => {
                if self.identity_dir().exists() {
                    fs::remove_dir_all(self.identity_dir())?;
                    removed.push("identity/".into());
                    info!("reset: removed identity/");
                }
                preserved.push("validator/".into());
                preserved.push("chain/".into());
                preserved.push("peerstore/".into());
            }
            ResetScope::Full => {
                for name in ["identity", "validator", "chain", "peerstore"] {
                    let p = self.root.join(name);
                    if p.exists() {
                        fs::remove_dir_all(&p)?;
                        removed.push(format!("{name}/"));
                        info!("reset: removed {name}/");
                    }
                }
            }
        }

        // Re‑create directory structure.
        self.ensure_all()?;

        Ok(ResetResult {
            scope: format!("{:?}", scope),
            dirs_removed: removed,
            dirs_preserved: preserved,
        })
    }

    // -------------------------------------------------------------------------
    // Node status
    // -------------------------------------------------------------------------

    /// Gather node status from on‑disk data (no RPC needed).
    pub fn status(&self) -> NodeStatus {
        let blocks_count = self
            .blocks_dir()
            .read_dir()
            .map(|rd| rd.filter_map(|e| e.ok()).count())
            .unwrap_or(0);

        let snapshots_count = self
            .snapshots_dir()
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

// -----------------------------------------------------------------------------
// ResetScope and ResetResult
// -----------------------------------------------------------------------------

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

// -----------------------------------------------------------------------------
// NodeStatus
// -----------------------------------------------------------------------------

/// Summary of node status from on‑disk data.
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

// -----------------------------------------------------------------------------
// Helper: directory size
// -----------------------------------------------------------------------------

/// Recursively compute directory size in bytes.
fn dir_size(path: &Path) -> u64 {
    if !path.exists() {
        return 0;
    }
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

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn test_layout_paths() {
        let layout = DataLayout::new("/var/lib/iona/val2");
        assert_eq!(
            layout.identity_dir(),
            PathBuf::from("/var/lib/iona/val2/identity")
        );
        assert_eq!(
            layout.validator_dir(),
            PathBuf::from("/var/lib/iona/val2/validator")
        );
        assert_eq!(
            layout.chain_dir(),
            PathBuf::from("/var/lib/iona/val2/chain")
        );
        assert_eq!(
            layout.peerstore_dir(),
            PathBuf::from("/var/lib/iona/val2/peerstore")
        );
        assert_eq!(
            layout.blocks_dir(),
            PathBuf::from("/var/lib/iona/val2/chain/blocks")
        );
        assert_eq!(
            layout.wal_dir(),
            PathBuf::from("/var/lib/iona/val2/chain/wal")
        );
        assert_eq!(
            layout.state_full_path(),
            PathBuf::from("/var/lib/iona/val2/chain/state/state_full.json")
        );
        assert_eq!(
            layout.validator_key_path(),
            PathBuf::from("/var/lib/iona/val2/validator/validator_key.json")
        );
        assert_eq!(
            layout.p2p_key_path(),
            PathBuf::from("/var/lib/iona/val2/identity/p2p_key.json")
        );
        assert_eq!(
            layout.peers_path(),
            PathBuf::from("/var/lib/iona/val2/peerstore/peers.json")
        );
    }

    #[test]
    fn test_fresh_layout() {
        let tmp = tempdir().unwrap();
        let layout = DataLayout::new(tmp.path());
        assert!(layout.is_fresh());
        assert!(!layout.has_chain_data());
        assert!(!layout.has_identity());
        assert!(!layout.has_validator_key());
    }

    #[test]
    fn test_ensure_all() {
        let tmp = tempdir().unwrap();
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
    fn test_keypair_roundtrip() {
        let tmp = tempdir().unwrap();
        let layout = DataLayout::new(tmp.path());
        layout.ensure_all().unwrap();

        let keypair = Ed25519Keypair::random();
        layout.save_p2p_keypair(&keypair).unwrap();
        let loaded = layout.load_p2p_keypair().unwrap();
        assert_eq!(keypair.to_seed(), loaded.to_seed());
    }

    #[test]
    fn test_generate_p2p_keypair() {
        let tmp = tempdir().unwrap();
        let layout = DataLayout::new(tmp.path());
        layout.ensure_all().unwrap();
        let keypair = layout.generate_p2p_keypair().unwrap();
        assert!(layout.p2p_key_path().exists());
        let loaded = layout.load_p2p_keypair().unwrap();
        assert_eq!(keypair.to_seed(), loaded.to_seed());
    }

    #[test]
    fn test_peer_id() {
        let tmp = tempdir().unwrap();
        let layout = DataLayout::new(tmp.path());
        layout.ensure_all().unwrap();
        layout.generate_p2p_keypair().unwrap();
        let id = layout.peer_id().unwrap();
        assert!(!id.is_empty());
    }

    #[test]
    fn test_reset_chain_only() {
        let tmp = tempdir().unwrap();
        let layout = DataLayout::new(tmp.path());
        layout.ensure_all().unwrap();

        fs::write(layout.p2p_key_path(), "identity").unwrap();
        fs::write(layout.state_full_path(), "{}").unwrap();
        fs::write(layout.peers_path(), "{}").unwrap();

        let result = layout.reset(ResetScope::Chain).unwrap();
        assert!(result.dirs_removed.contains(&"chain/".to_string()));
        assert!(result.dirs_preserved.contains(&"identity/".to_string()));

        assert!(layout.p2p_key_path().exists());
        assert!(!layout.state_full_path().exists());
        assert!(layout.peers_path().exists());
    }

    #[test]
    fn test_reset_identity_only() {
        let tmp = tempdir().unwrap();
        let layout = DataLayout::new(tmp.path());
        layout.ensure_all().unwrap();

        fs::write(layout.p2p_key_path(), "identity").unwrap();
        fs::write(layout.state_full_path(), "{}").unwrap();

        let result = layout.reset(ResetScope::Identity).unwrap();
        assert!(result.dirs_removed.contains(&"identity/".to_string()));
        assert!(result.dirs_preserved.contains(&"chain/".to_string()));

        assert!(!layout.p2p_key_path().exists());
        assert!(layout.state_full_path().exists());
    }

    #[test]
    fn test_reset_full() {
        let tmp = tempdir().unwrap();
        let layout = DataLayout::new(tmp.path());
        layout.ensure_all().unwrap();

        fs::write(layout.p2p_key_path(), "identity").unwrap();
        fs::write(layout.state_full_path(), "{}").unwrap();
        fs::write(layout.peers_path(), "{}").unwrap();

        let result = layout.reset(ResetScope::Full).unwrap();
        assert!(!result.dirs_removed.is_empty());

        assert!(!layout.p2p_key_path().exists());
        assert!(!layout.state_full_path().exists());
        assert!(!layout.peers_path().exists());
    }

    #[test]
    fn test_status() {
        let tmp = tempdir().unwrap();
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
