//! Persistent peerstore for IONA v28.
//!
//! Saves known peers with their multiaddresses and last-seen timestamps
//! to `peerstore/peers.json` so they survive restarts.
//!
//! Also supports `--print-peer-id` and `--print-multiaddr` for generating
//! correct bootnode entries.

use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    fs, io,
    path::Path,
    time::{SystemTime, UNIX_EPOCH},
};

/// A known peer entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerEntry {
    /// Peer ID (base58-encoded libp2p PeerId).
    pub peer_id: String,
    /// Known multiaddresses for this peer.
    pub addrs: Vec<String>,
    /// Unix timestamp of last successful connection.
    pub last_seen: u64,
    /// Number of successful connections.
    pub success_count: u64,
    /// Number of failed connection attempts.
    pub fail_count: u64,
    /// Optional human label (e.g. "val2", "rpc").
    #[serde(default)]
    pub label: String,
}

/// Persistent peerstore.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct Peerstore {
    pub peers: BTreeMap<String, PeerEntry>,
}

impl Peerstore {
    /// Load from a JSON file (returns empty store if file doesn't exist).
    pub fn load(path: impl AsRef<Path>) -> io::Result<Self> {
        let p = path.as_ref();
        if !p.exists() {
            return Ok(Self::default());
        }
        let s = fs::read_to_string(p)?;
        serde_json::from_str(&s).map_err(|e| {
            io::Error::new(io::ErrorKind::InvalidData, format!("peerstore parse: {e}"))
        })
    }

    /// Save to a JSON file (atomic: write tmp then rename).
    pub fn save(&self, path: impl AsRef<Path>) -> io::Result<()> {
        let p = path.as_ref();
        if let Some(parent) = p.parent() {
            fs::create_dir_all(parent)?;
        }
        let tmp = p.with_extension("json.tmp");
        let out = serde_json::to_string_pretty(self).map_err(|e| {
            io::Error::new(io::ErrorKind::InvalidData, format!("peerstore encode: {e}"))
        })?;
        fs::write(&tmp, &out)?;
        fs::rename(&tmp, p)?;
        Ok(())
    }

    /// Record a successful connection to a peer.
    pub fn record_success(&mut self, peer_id: &str, addrs: &[String]) {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);

        let entry = self
            .peers
            .entry(peer_id.to_string())
            .or_insert_with(|| PeerEntry {
                peer_id: peer_id.to_string(),
                addrs: Vec::new(),
                last_seen: 0,
                success_count: 0,
                fail_count: 0,
                label: String::new(),
            });

        entry.last_seen = now;
        entry.success_count += 1;
        // Merge addresses (deduplicate).
        for addr in addrs {
            if !entry.addrs.contains(addr) {
                entry.addrs.push(addr.clone());
            }
        }
    }

    /// Record a failed connection attempt.
    pub fn record_failure(&mut self, peer_id: &str) {
        if let Some(entry) = self.peers.get_mut(peer_id) {
            entry.fail_count += 1;
        }
    }

    /// Get all known peer addresses for bootstrapping.
    pub fn bootnode_addrs(&self) -> Vec<String> {
        let mut addrs = Vec::new();
        for entry in self.peers.values() {
            for addr in &entry.addrs {
                // Append /p2p/<peer_id> if not already present.
                if addr.contains("/p2p/") {
                    addrs.push(addr.clone());
                } else {
                    addrs.push(format!("{}/p2p/{}", addr, entry.peer_id));
                }
            }
        }
        addrs
    }

    /// Number of known peers.
    pub fn len(&self) -> usize {
        self.peers.len()
    }

    /// Is the peerstore empty?
    pub fn is_empty(&self) -> bool {
        self.peers.is_empty()
    }

    /// Prune peers not seen in `max_age_secs` seconds.
    pub fn prune(&mut self, max_age_secs: u64) {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);

        self.peers
            .retain(|_, entry| now.saturating_sub(entry.last_seen) < max_age_secs);
    }
}

/// Generate a bootnode multiaddr string with peer ID.
///
/// Example: `/ip4/10.0.1.2/tcp/30334/p2p/12D3KooWAbCdEf...`
pub fn format_bootnode(ip: &str, port: u16, peer_id: &str) -> String {
    format!("/ip4/{}/tcp/{}/p2p/{}", ip, port, peer_id)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_peerstore_empty() {
        let ps = Peerstore::default();
        assert!(ps.is_empty());
        assert_eq!(ps.len(), 0);
    }

    #[test]
    fn test_record_success() {
        let mut ps = Peerstore::default();
        ps.record_success("12D3KooWAbCd", &["/ip4/1.2.3.4/tcp/7001".into()]);
        assert_eq!(ps.len(), 1);
        let entry = ps.peers.get("12D3KooWAbCd").unwrap();
        assert_eq!(entry.success_count, 1);
        assert_eq!(entry.addrs.len(), 1);
        assert!(entry.last_seen > 0);

        // Second success with same addr — should not duplicate.
        ps.record_success("12D3KooWAbCd", &["/ip4/1.2.3.4/tcp/7001".into()]);
        let entry = ps.peers.get("12D3KooWAbCd").unwrap();
        assert_eq!(entry.success_count, 2);
        assert_eq!(entry.addrs.len(), 1);

        // New address.
        ps.record_success("12D3KooWAbCd", &["/ip4/5.6.7.8/tcp/7001".into()]);
        let entry = ps.peers.get("12D3KooWAbCd").unwrap();
        assert_eq!(entry.addrs.len(), 2);
    }

    #[test]
    fn test_record_failure() {
        let mut ps = Peerstore::default();
        ps.record_success("peer1", &["/ip4/1.2.3.4/tcp/7001".into()]);
        ps.record_failure("peer1");
        let entry = ps.peers.get("peer1").unwrap();
        assert_eq!(entry.fail_count, 1);
        assert_eq!(entry.success_count, 1);
    }

    #[test]
    fn test_bootnode_addrs() {
        let mut ps = Peerstore::default();
        ps.record_success("12D3KooW1", &["/ip4/1.2.3.4/tcp/7001".into()]);
        ps.record_success("12D3KooW2", &["/ip4/5.6.7.8/tcp/7002".into()]);

        let addrs = ps.bootnode_addrs();
        assert_eq!(addrs.len(), 2);
        assert!(addrs[0].contains("/p2p/12D3KooW1"));
        assert!(addrs[1].contains("/p2p/12D3KooW2"));
    }

    #[test]
    fn test_roundtrip() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("peerstore").join("peers.json");

        let mut ps = Peerstore::default();
        ps.record_success("peer1", &["/ip4/1.2.3.4/tcp/7001".into()]);
        ps.save(&path).unwrap();

        let ps2 = Peerstore::load(&path).unwrap();
        assert_eq!(ps2.len(), 1);
        assert!(ps2.peers.contains_key("peer1"));
    }

    #[test]
    fn test_format_bootnode() {
        let bn = format_bootnode("10.0.1.2", 30334, "12D3KooWAbCd");
        assert_eq!(bn, "/ip4/10.0.1.2/tcp/30334/p2p/12D3KooWAbCd");
    }

    #[test]
    fn test_prune() {
        let mut ps = Peerstore::default();
        ps.record_success("recent", &["/ip4/1.2.3.4/tcp/7001".into()]);

        // Manually set an old peer.
        ps.peers.insert(
            "old".into(),
            PeerEntry {
                peer_id: "old".into(),
                addrs: vec!["/ip4/9.8.7.6/tcp/7001".into()],
                last_seen: 1000, // very old
                success_count: 1,
                fail_count: 0,
                label: String::new(),
            },
        );

        assert_eq!(ps.len(), 2);
        ps.prune(3600); // 1 hour max age
        assert_eq!(ps.len(), 1); // "old" should be pruned
        assert!(ps.peers.contains_key("recent"));
    }
}
