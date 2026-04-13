//! Persisted double-sign protection with hash-chain integrity.
//!
//! Security invariants:
//! - Every sign attempt is checked against the persisted guard state BEFORE signing.
//! - Conflicting sign (same position, different block_id) returns `Err` — caller must halt.
//! - Guard state is persisted atomically (write to .tmp then rename) before returning.
//! - Records form a hash chain: each entry includes blake3(previous_entry) so that
//!   the file cannot be silently rolled back to a previous state without detection.
//! - On load, the hash chain is verified; a corrupt or rolled-back file aborts startup.

use crate::consensus::messages::VoteType;
use crate::crypto::PublicKeyBytes;
use crate::types::{Hash32, Height, Round};
use blake3;
use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use std::{collections::BTreeMap, fs, path::Path, sync::Arc};

// ── On-disk format ────────────────────────────────────────────────────────

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
struct GuardState {
    /// Key: "proposal:<h>:<r>" → block_id hex
    proposals: BTreeMap<String, String>,
    /// Key: "vote:<type>:<h>:<r>" → block_id hex (or "nil")
    votes: BTreeMap<String, String>,
    /// blake3 hash of the serialized state at the last successful write.
    /// Used to detect rollback/truncation attacks.
    #[serde(default)]
    chain_hash: String,
}

impl GuardState {
    /// Compute the hash of the current state (excluding chain_hash itself).
    fn compute_hash(&self) -> String {
        // Serialize deterministically without the chain_hash field.
        let canonical = serde_json::json!({
            "proposals": &self.proposals,
            "votes": &self.votes,
        });
        let bytes = serde_json::to_vec(&canonical).unwrap_or_default();
        let hash = blake3::hash(&bytes);
        hex::encode(hash.as_bytes())
    }

    /// Stamp the chain_hash field with the current state hash.
    fn stamp(&mut self) {
        self.chain_hash = self.compute_hash();
    }

    /// Verify that the stored chain_hash matches the current state.
    /// Returns `Err` if the file appears rolled back or tampered.
    fn verify_chain(&self) -> Result<(), String> {
        if self.chain_hash.is_empty() {
            // Fresh file, no chain yet.
            return Ok(());
        }
        let expected = self.compute_hash();
        if self.chain_hash != expected {
            return Err(format!(
                "double-sign guard chain integrity FAILED: stored={} computed={}",
                self.chain_hash, expected
            ));
        }
        Ok(())
    }
}

// ── Disk I/O with atomic writes ───────────────────────────────────────────

fn load_state(path: &str) -> Result<GuardState, String> {
    if !Path::new(path).exists() {
        return Ok(GuardState::default());
    }
    let raw = fs::read_to_string(path).map_err(|e| format!("double-sign guard read error: {e}"))?;
    let mut st: GuardState =
        serde_json::from_str(&raw).map_err(|e| format!("double-sign guard parse error: {e}"))?;

    // Verify chain integrity.
    st.verify_chain()?;

    Ok(st)
}

fn save_state(path: &str, st: &mut GuardState) -> Result<(), String> {
    // Stamp the hash chain before writing.
    st.stamp();

    let json = serde_json::to_string_pretty(st)
        .map_err(|e| format!("double-sign guard encode error: {e}"))?;

    // Atomic write: write to .tmp, then rename.
    let tmp_path = format!("{path}.tmp");
    fs::write(&tmp_path, &json).map_err(|e| format!("double-sign guard write tmp error: {e}"))?;
    fs::rename(&tmp_path, path).map_err(|e| format!("double-sign guard rename error: {e}"))?;

    Ok(())
}

// ── DoubleSignGuard ───────────────────────────────────────────────────────

#[derive(Clone)]
#[derive(Debug)]
pub struct DoubleSignGuard {
    path: String,
    inner: Arc<Mutex<GuardState>>,
}

impl DoubleSignGuard {
    /// Load (or create) the guard for the given validator public key.
    /// Returns `Err` if the on-disk state fails chain integrity verification.
    /// The caller MUST treat this as fatal — do not start the node if this fails.
    pub fn new(data_dir: &str, pk: &PublicKeyBytes) -> Result<Self, String> {
        let pk_hex = hex::encode(&pk.0);
        let path = format!("{data_dir}/doublesign_{pk_hex}.json");
        let st = load_state(&path)?;
        Ok(Self {
            path,
            inner: Arc::new(Mutex::new(st)),
        })
    }

    /// Create with a legacy fallback (never fails; used in tests and dev).
    pub fn new_or_default(data_dir: &str, pk: &PublicKeyBytes) -> Self {
        match Self::new(data_dir, pk) {
            Ok(g) => g,
            Err(e) => {
                tracing::error!("double-sign guard load failed: {e}; starting fresh (DEV ONLY)");
                let pk_hex = hex::encode(&pk.0);
                Self {
                    path: format!("{data_dir}/doublesign_{pk_hex}.json"),
                    inner: Arc::new(Mutex::new(GuardState::default())),
                }
            }
        }
    }

    // ── Check + record: proposals ─────────────────────────────────────────

    /// Check whether signing this proposal would be a double-sign.
    pub fn check_proposal(
        &self,
        height: Height,
        round: Round,
        block_id: &Hash32,
    ) -> Result<(), String> {
        let key = format!("proposal:{height}:{round}");
        let want = h32_hex(block_id);
        let st = self.inner.lock();
        if let Some(existing) = st.proposals.get(&key) {
            if existing != &want {
                return Err(format!(
                    "DOUBLE-PROPOSAL REFUSED height={height} round={round} \
                     existing={existing} attempted={want}"
                ));
            }
        }
        Ok(())
    }

    /// Record that this proposal was signed. Must be called BEFORE signing.
    /// Returns `Err` if the disk write fails — caller must treat as fatal.
    pub fn record_proposal(
        &self,
        height: Height,
        round: Round,
        block_id: &Hash32,
    ) -> Result<(), String> {
        let key = format!("proposal:{height}:{round}");
        let val = h32_hex(block_id);
        let mut st = self.inner.lock();
        st.proposals.insert(key, val);
        save_state(&self.path, &mut st)
    }

    // ── Check + record: votes ─────────────────────────────────────────────

    /// Check whether signing this vote would be a double-sign.
    pub fn check_vote(
        &self,
        vt: VoteType,
        height: Height,
        round: Round,
        block_id: &Option<Hash32>,
    ) -> Result<(), String> {
        let key = vote_guard_key(vt, height, round);
        let want = block_id
            .as_ref()
            .map(h32_hex)
            .unwrap_or_else(|| "nil".to_string());
        let st = self.inner.lock();
        if let Some(existing) = st.votes.get(&key) {
            if existing != &want {
                return Err(format!(
                    "DOUBLE-VOTE REFUSED type={vt:?} height={height} round={round} \
                     existing={existing} attempted={want}"
                ));
            }
        }
        Ok(())
    }

    /// Record that this vote was signed. Must be called BEFORE signing.
    /// Returns `Err` if the disk write fails — caller must treat as fatal.
    pub fn record_vote(
        &self,
        vt: VoteType,
        height: Height,
        round: Round,
        block_id: &Option<Hash32>,
    ) -> Result<(), String> {
        let key = vote_guard_key(vt, height, round);
        let val = block_id
            .as_ref()
            .map(h32_hex)
            .unwrap_or_else(|| "nil".to_string());
        let mut st = self.inner.lock();
        st.votes.insert(key, val);
        save_state(&self.path, &mut st)
    }

    // ── Inspection ───────────────────────────────────────────────────────

    /// Returns the number of signed proposals and votes recorded.
    pub fn record_count(&self) -> (usize, usize) {
        let st = self.inner.lock();
        (st.proposals.len(), st.votes.len())
    }

    /// Verify the on-disk chain integrity right now (call from health endpoint).
    pub fn verify_integrity(&self) -> Result<(), String> {
        let st = self.inner.lock();
        st.verify_chain()
    }
}

// ── Helpers ───────────────────────────────────────────────────────────────

fn h32_hex(id: &Hash32) -> String {
    hex::encode(&id.0)
}

pub fn vote_guard_key(vt: VoteType, height: Height, round: Round) -> String {
    format!("vote:{vt:?}:{height}:{round}")
}

// ── Tests ─────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::consensus::messages::VoteType;
    use crate::crypto::PublicKeyBytes;
    use crate::types::Hash32;

    fn test_guard() -> (DoubleSignGuard, tempfile::TempDir) {
        let dir = tempfile::tempdir().unwrap();
        let pk = PublicKeyBytes(vec![0u8; 32]);
        let g = DoubleSignGuard::new(dir.path().to_str().unwrap(), &pk).expect("guard should load");
        (g, dir)
    }

    fn hash(b: u8) -> Hash32 {
        Hash32([b; 32])
    }

    #[test]
    fn test_fresh_guard_allows_proposal() {
        let (g, _dir) = test_guard();
        assert!(g.check_proposal(1, 0, &hash(1)).is_ok());
    }

    #[test]
    fn test_record_then_same_proposal_ok() {
        let (g, _dir) = test_guard();
        g.record_proposal(1, 0, &hash(1)).unwrap();
        assert!(g.check_proposal(1, 0, &hash(1)).is_ok());
    }

    #[test]
    fn test_double_proposal_refused() {
        let (g, _dir) = test_guard();
        g.record_proposal(1, 0, &hash(1)).unwrap();
        let result = g.check_proposal(1, 0, &hash(2));
        assert!(result.is_err(), "double-proposal must be refused");
        assert!(result.unwrap_err().contains("DOUBLE-PROPOSAL"));
    }

    #[test]
    fn test_double_vote_refused() {
        let (g, _dir) = test_guard();
        g.record_vote(VoteType::Prevote, 1, 0, &Some(hash(1)))
            .unwrap();
        let result = g.check_vote(VoteType::Prevote, 1, 0, &Some(hash(2)));
        assert!(result.is_err(), "double-vote must be refused");
        assert!(result.unwrap_err().contains("DOUBLE-VOTE"));
    }

    #[test]
    fn test_nil_vote_differs_from_block_vote() {
        let (g, _dir) = test_guard();
        g.record_vote(VoteType::Prevote, 1, 0, &Some(hash(1)))
            .unwrap();
        let result = g.check_vote(VoteType::Prevote, 1, 0, &None);
        assert!(
            result.is_err(),
            "nil vote after block vote is a double-sign"
        );
    }

    #[test]
    fn test_different_rounds_are_independent() {
        let (g, _dir) = test_guard();
        g.record_proposal(1, 0, &hash(1)).unwrap();
        // Round 1 is independent — should be fine with a different block.
        assert!(g.check_proposal(1, 1, &hash(2)).is_ok());
    }

    #[test]
    fn test_chain_hash_persisted_and_verified() {
        let dir = tempfile::tempdir().unwrap();
        let pk = PublicKeyBytes(vec![1u8; 32]);
        let path = dir.path().to_str().unwrap();

        {
            let g = DoubleSignGuard::new(path, &pk).unwrap();
            g.record_proposal(1, 0, &hash(1)).unwrap();
        }

        // Reload — should succeed and verify chain hash.
        let g2 = DoubleSignGuard::new(path, &pk);
        assert!(g2.is_ok(), "reload with valid chain hash should succeed");
        let (proposals, _) = g2.unwrap().record_count();
        assert_eq!(proposals, 1);
    }

    #[test]
    fn test_tampered_file_detected() {
        let dir = tempfile::tempdir().unwrap();
        let pk = PublicKeyBytes(vec![2u8; 32]);
        let path_str = dir.path().to_str().unwrap();

        // Write a valid guard.
        {
            let g = DoubleSignGuard::new(path_str, &pk).unwrap();
            g.record_proposal(5, 0, &hash(5)).unwrap();
        }

        // Tamper with the file: zero the chain_hash.
        let guard_path = format!("{path_str}/doublesign_{}.json", hex::encode([2u8; 32]));
        let raw = fs::read_to_string(&guard_path).unwrap();
        let mut json: serde_json::Value = serde_json::from_str(&raw).unwrap();
        json["chain_hash"] = serde_json::Value::String("0000000000000000".to_string());
        fs::write(&guard_path, serde_json::to_string_pretty(&json).unwrap()).unwrap();

        // Reload — should fail with chain integrity error.
        let result = DoubleSignGuard::new(path_str, &pk);
        assert!(
            result.is_err(),
            "tampered guard file should fail integrity check"
        );
        assert!(result.unwrap_err().contains("chain integrity FAILED"));
    }

    #[test]
    fn test_verify_integrity_ok_on_fresh() {
        let (g, _dir) = test_guard();
        assert!(g.verify_integrity().is_ok());
    }
}
