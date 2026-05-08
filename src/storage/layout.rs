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
//!     wal/                 # write‑ahead log segments
//!     state/               # state_full.json, stakes.json, evidence
//!     receipts/            # transaction receipts
//!     snapshots/           # periodic state snapshots
//!   peerstore/
//!     peers.json           # known peers with last‑seen timestamps
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
//! layout.ensure_all()?;
//! let peer_id = layout.peer_id()?;
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```

use crate::crypto::ed25519::{Ed25519Keypair, Ed25519Signer};
use serde::{Deserialize, Serialize};
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use thiserror::Error;
use tracing::{debug, info, warn};

// -----------------------------------------------------------------------------
// Constants
// -----------------------------------------------------------------------------

/// File name for the P2P key.
const P2P_KEY_FILE: &str = "p2p_key.json";

/// File name for node metadata.
const NODE_META_FILE: &str = "node_meta.json";

/// File name for the plaintext validator key.
const VALIDATOR_KEY_FILE: &str = "validator_key.json";

/// File name for the encrypted validator key.
const VALIDATOR_KEY_ENC_FILE: &str = "validator_key.enc";

/// File name for the full state JSON.
const STATE_FULL_FILE: &str = "state_full.json";

/// File name for the stakes JSON.
const STAKES_FILE: &str = "stakes.json";

/// File name for the evidence store (JSONL).
const EVIDENCE_FILE: &str = "evidence.jsonl";

/// File name for the schema metadata.
const SCHEMA_FILE: &str = "schema.json";

/// File name for the transaction index.
const TX_INDEX_FILE: &str = "tx_index.json";

/// File name for the known peers list.
const PEERS_FILE: &str = "peers.json";

/// File name for the quarantine list.
const QUARANTINE_FILE: &str = "quarantine.json";

/// Subdirectory names.
const IDENTITY_DIR: &str = "identity";
const VALIDATOR_DIR: &str = "validator";
const CHAIN_DIR: &str = "chain";
const PEERSTORE_DIR: &str = "peerstore";
const BLOCKS_DIR: &str = "blocks";
const WAL_DIR: &str = "wal";
const STATE_DIR: &str = "state";
const RECEIPTS_DIR: &str = "receipts";
const SNAPSHOTS_DIR: &str = "snapshots";

// -----------------------------------------------------------------------------
// Errors
// -----------------------------------------------------------------------------

/// Errors that can occur during layout operations.
#[derive(Debug, Error)]
pub enum LayoutError {
    #[error("I/O error: {source}")]
    Io {
        #[from]
        source: io::Error,
    },

    #[error("JSON error: {source}")]
    Json {
        #[from]
        source: serde_json::Error,
    },

    #[error("invalid hex: {source}")]
    Hex {
        #[from]
        source: hex::FromHexError,
    },

    #[error("invalid seed length: expected 32 bytes, got {len}")]
    InvalidSeedLength { len: usize },

    #[error("invalid peer ID derivation")]
    InvalidPeerId,
}

pub type LayoutResult<T> = Result<T, LayoutError>;

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
    #[must_use]
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self { root: root.into() }
    }

    // -------------------------------------------------------------------------
    // Directory accessors
    // -------------------------------------------------------------------------

    /// Directory for node identity (P2P key, node metadata).
    #[must_use]
    pub fn identity_dir(&self) -> PathBuf {
        self.root.join(IDENTITY_DIR)
    }

    /// Directory for validator signing key (if any).
    #[must_use]
    pub fn validator_dir(&self) -> PathBuf {
        self.root.join(VALIDATOR_DIR)
    }

    /// Directory for chain data (blocks, WAL, state, receipts, snapshots).
    #[must_use]
    pub fn chain_dir(&self) -> PathBuf {
        self.root.join(CHAIN_DIR)
    }

    /// Directory for peer store (known peers, quarantine).
    #[must_use]
    pub fn peerstore_dir(&self) -> PathBuf {
        self.root.join(PEERSTORE_DIR)
    }

    // -------------------------------------------------------------------------
    // Chain sub‑directories
    // -------------------------------------------------------------------------

    /// Directory for committed blocks.
    #[must_use]
    pub fn blocks_dir(&self) -> PathBuf {
        self.chain_dir().join(BLOCKS_DIR)
    }

    /// Directory for write‑ahead log segments.
    #[must_use]
    pub fn wal_dir(&self) -> PathBuf {
        self.chain_dir().join(WAL_DIR)
    }

    /// Directory for state files.
    #[must_use]
    pub fn state_dir(&self) -> PathBuf {
        self.chain_dir().join(STATE_DIR)
    }

    /// Directory for transaction receipts.
    #[must_use]
    pub fn receipts_dir(&self) -> PathBuf {
        self.chain_dir().join(RECEIPTS_DIR)
    }

    /// Directory for snapshots.
    #[must_use]
    pub fn snapshots_dir(&self) -> PathBuf {
        self.chain_dir().join(SNAPSHOTS_DIR)
    }

    // -------------------------------------------------------------------------
    // Identity files
    // -------------------------------------------------------------------------

    /// Path to the P2P key file (JSON).
    #[must_use]
    pub fn p2p_key_path(&self) -> PathBuf {
        self.identity_dir().join(P2P_KEY_FILE)
    }

    /// Path to the node metadata file.
    #[must_use]
    pub fn node_meta_path(&self) -> PathBuf {
        self.identity_dir().join(NODE_META_FILE)
    }

    // -------------------------------------------------------------------------
    // Validator files
    // -------------------------------------------------------------------------

    /// Path to the plaintext validator key file (JSON).
    #[must_use]
    pub fn validator_key_path(&self) -> PathBuf {
        self.validator_dir().join(VALIDATOR_KEY_FILE)
    }

    /// Path to the encrypted validator key file.
    #[must_use]
    pub fn validator_key_enc_path(&self) -> PathBuf {
        self.validator_dir().join(VALIDATOR_KEY_ENC_FILE)
    }

    // -------------------------------------------------------------------------
    // Chain state files
    // -------------------------------------------------------------------------

    /// Path to the full state JSON file.
    #[must_use]
    pub fn state_full_path(&self) -> PathBuf {
        self.state_dir().join(STATE_FULL_FILE)
    }

    /// Path to the stakes file.
    #[must_use]
    pub fn stakes_path(&self) -> PathBuf {
        self.state_dir().join(STAKES_FILE)
    }

    /// Path to the evidence store (JSONL).
    #[must_use]
    pub fn evidence_path(&self) -> PathBuf {
        self.state_dir().join(EVIDENCE_FILE)
    }

    /// Path to the schema metadata file.
    #[must_use]
    pub fn schema_path(&self) -> PathBuf {
        self.state_dir().join(SCHEMA_FILE)
    }

    /// Path to the transaction index file.
    #[must_use]
    pub fn tx_index_path(&self) -> PathBuf {
        self.state_dir().join(TX_INDEX_FILE)
    }

    // -------------------------------------------------------------------------
    // Peerstore files
    // -------------------------------------------------------------------------

    /// Path to the known peers file.
    #[must_use]
    pub fn peers_path(&self) -> PathBuf {
        self.peerstore_dir().join(PEERS_FILE)
    }

    /// Path to the quarantine list file.
    #[must_use]
    pub fn quarantine_path(&self) -> PathBuf {
        self.peerstore_dir().join(QUARANTINE_FILE)
    }

    // -------------------------------------------------------------------------
    // Directory creation and checks
    // -------------------------------------------------------------------------

    /// Ensure all required directories exist.
    pub fn ensure_all(&self) -> LayoutResult<()> {
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
    pub fn load_p2p_keypair(&self) -> LayoutResult<Ed25519Keypair> {
        let path = self.p2p_key_path();
        let content = fs::read_to_string(&path)?;
        let seed_hex: String = serde_json::from_str(&content)?;
        let seed = hex::decode(seed_hex)?;
        if seed.len() != 32 {
            return Err(LayoutError::InvalidSeedLength { len: seed.len() });
        }
        let mut seed_arr = [0u8; 32];
        seed_arr.copy_from_slice(&seed);
        Ok(Ed25519Keypair::from_seed(seed_arr))
    }

    /// Save the P2P keypair (libp2p) as an Ed25519 keypair.
    pub fn save_p2p_keypair(&self, keypair: &Ed25519Keypair) -> LayoutResult<()> {
        let path = self.p2p_key_path();
        let seed = keypair.to_seed();
        let seed_hex = hex::encode(seed);
        let json = serde_json::to_string_pretty(&seed_hex)?;
        fs::write(&path, json)?;
        debug!(path = %path.display(), "saved P2P keypair");
        Ok(())
    }

    /// Generate a new random P2P keypair and save it.
    pub fn generate_p2p_keypair(&self) -> LayoutResult<Ed25519Keypair> {
        let keypair = Ed25519Keypair::random();
        self.save_p2p_keypair(&keypair)?;
        Ok(keypair)
    }

    /// Load the validator keypair (Ed25519) from the plaintext file.
    pub fn load_validator_keypair(&self) -> LayoutResult<Ed25519Keypair> {
        let path = self.validator_key_path();
        let content = fs::read_to_string(&path)?;
        let seed_hex: String = serde_json::from_str(&content)?;
        let seed = hex::decode(seed_hex)?;
        if seed.len() != 32 {
            return Err(LayoutError::InvalidSeedLength { len: seed.len() });
        }
        let mut seed_arr = [0u8; 32];
        seed_arr.copy_from_slice(&seed);
        Ok(Ed25519Keypair::from_seed(seed_arr))
    }

    /// Save the validator keypair to the plaintext file.
    pub fn save_validator_keypair(&self, keypair: &Ed25519Keypair) -> LayoutResult<()> {
        let path = self.validator_key_path();
        let seed = keypair.to_seed();
        let seed_hex = hex::encode(seed);
        let json = serde_json::to_string_pretty(&seed_hex)?;
        fs::write(&path, json)?;
        debug!(path = %path.display(), "saved validator keypair");
        Ok(())
    }

    /// Generate a new random validator keypair and save it.
    pub fn generate_validator_keypair(&self) -> LayoutResult<Ed25519Keypair> {
        let keypair = Ed25519Keypair::random();
        self.save_validator_keypair(&keypair)?;
        Ok(keypair)
    }

    /// Get the peer ID (libp2p) from the P2P key.
    pub fn peer_id(&self) -> LayoutResult<String> {
        let keypair = self.load_p2p_keypair()?;
        let public_key = keypair.public_key();
        let hash = blake3::hash(&public_key.0);
        Ok(hex::encode(&hash.as_bytes()[..16]))
    }

    /// Create an Ed25519 signer from the validator key.
    pub fn validator_signer(&self) -> LayoutResult<Ed25519Signer> {
        let keypair = self.load_validator_keypair()?;
        Ok(Ed25519Signer::from_keypair(keypair))
    }

    // -------------------------------------------------------------------------
    // Reset operations
    // -------------------------------------------------------------------------

    /// Perform a controlled reset of the data directory.
    pub fn reset(&self, scope: ResetScope) -> LayoutResult<ResetResult> {
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
                for name in [IDENTITY_DIR, VALIDATOR_DIR, CHAIN_DIR, PEERSTORE_DIR] {
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
    fn test_fresh_layout() -> LayoutResult<()> {
        let tmp = tempdir()?;
        let layout = DataLayout::new(tmp.path());
        assert!(layout.is_fresh());
        assert!(!layout.has_chain_data());
        assert!(!layout.has_identity());
        assert!(!layout.has_validator_key());
        Ok(())
    }

    #[test]
    fn test_ensure_all() -> LayoutResult<()> {
        let tmp = tempdir()?;
        let layout = DataLayout::new(tmp.path());
        layout.ensure_all()?;
        assert!(layout.identity_dir().exists());
        assert!(layout.validator_dir().exists());
        assert!(layout.blocks_dir().exists());
        assert!(layout.wal_dir().exists());
        assert!(layout.state_dir().exists());
        assert!(layout.receipts_dir().exists());
        assert!(layout.snapshots_dir().exists());
        assert!(layout.peerstore_dir().exists());
        Ok(())
    }

    #[test]
    fn test_keypair_roundtrip() -> LayoutResult<()> {
        let tmp = tempdir()?;
        let layout = DataLayout::new(tmp.path());
        layout.ensure_all()?;
        let keypair = Ed25519Keypair::random();
        layout.save_p2p_keypair(&keypair)?;
        let loaded = layout.load_p2p_keypair()?;
        assert_eq!(keypair.to_seed(), loaded.to_seed());
        Ok(())
    }

    #[test]
    fn test_generate_p2p_keypair() -> LayoutResult<()> {
        let tmp = tempdir()?;
        let layout = DataLayout::new(tmp.path());
        layout.ensure_all()?;
        let keypair = layout.generate_p2p_keypair()?;
        assert!(layout.p2p_key_path().exists());
        let loaded = layout.load_p2p_keypair()?;
        assert_eq!(keypair.to_seed(), loaded.to_seed());
        Ok(())
    }

    #[test]
    fn test_peer_id() -> LayoutResult<()> {
        let tmp = tempdir()?;
        let layout = DataLayout::new(tmp.path());
        layout.ensure_all()?;
        layout.generate_p2p_keypair()?;
        let id = layout.peer_id()?;
        assert!(!id.is_empty());
        Ok(())
    }

    #[test]
    fn test_reset_chain_only() -> LayoutResult<()> {
        let tmp = tempdir()?;
        let layout = DataLayout::new(tmp.path());
        layout.ensure_all()?;
        fs::write(layout.p2p_key_path(), "identity")?;
        fs::write(layout.state_full_path(), "{}")?;
        fs::write(layout.peers_path(), "{}")?;
        let result = layout.reset(ResetScope::Chain)?;
        assert!(result.dirs_removed.contains(&"chain/".to_string()));
        assert!(result.dirs_preserved.contains(&"identity/".to_string()));
        assert!(layout.p2p_key_path().exists());
        assert!(!layout.state_full_path().exists());
        assert!(layout.peers_path().exists());
        Ok(())
    }

    #[test]
    fn test_reset_identity_only() -> LayoutResult<()> {
        let tmp = tempdir()?;
        let layout = DataLayout::new(tmp.path());
        layout.ensure_all()?;
        fs::write(layout.p2p_key_path(), "identity")?;
        fs::write(layout.state_full_path(), "{}")?;
        let result = layout.reset(ResetScope::Identity)?;
        assert!(result.dirs_removed.contains(&"identity/".to_string()));
        assert!(result.dirs_preserved.contains(&"chain/".to_string()));
        assert!(!layout.p2p_key_path().exists());
        assert!(layout.state_full_path().exists());
        Ok(())
    }

    #[test]
    fn test_reset_full() -> LayoutResult<()> {
        let tmp = tempdir()?;
        let layout = DataLayout::new(tmp.path());
        layout.ensure_all()?;
        fs::write(layout.p2p_key_path(), "identity")?;
        fs::write(layout.state_full_path(), "{}")?;
        fs::write(layout.peers_path(), "{}")?;
        let result = layout.reset(ResetScope::Full)?;
        assert!(!result.dirs_removed.is_empty());
        assert!(!layout.p2p_key_path().exists());
        assert!(!layout.state_full_path().exists());
        assert!(!layout.peers_path().exists());
        Ok(())
    }

    #[test]
    fn test_status() -> LayoutResult<()> {
        let tmp = tempdir()?;
        let layout = DataLayout::new(tmp.path());
        layout.ensure_all()?;
        let status = layout.status();
        assert_eq!(status.blocks_count, 0);
        assert_eq!(status.snapshots_count, 0);
        assert!(!status.has_identity);
        assert!(!status.has_validator_key);
        assert!(!status.has_chain_data);
        assert!(status.schema_version.is_none());
        Ok(())
    }
}
