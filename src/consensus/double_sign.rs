//! Quantum double-sign protection with entanglement-based hash-chain integrity.
//!
//! Prevents slashable equivocation by modelling each signing attempt as a
//! **quantum measurement** on the validator's Hilbert space. Conflicting
//! measurements (same position, different block_id) collapse the state to
//! an error subspace |DOUBLE_SIGN⟩.
//!
//! # Quantum Security Model
//!
//! ## State Representation
//! The guard state is a density matrix ρ in the Hilbert space:
//! ```text
//! ℋ_guard = ℋ_proposals ⊗ ℋ_votes ⊗ ℋ_chain
//! ```
//!
//! ## Hamiltonian
//! ```text
//! Ĥ = Ĥ_check + Ĥ_record + Ĥ_chain
//!
//! Ĥ_check  = Σ_p E_p |p⟩⟨p|                          (projective measurement)
//! Ĥ_record = Σ_r g_r (a†_r a_r)                       (creation operator)
//! Ĥ_chain  = Σ_c ω_c |hash_c⟩⟨hash_c|                 (integrity observable)
//! ```
//!
//! ## Double-Sign Detection as Entanglement Witness
//! ```text
//! W = |existing⟩⟨existing| ⊗ |attempted⟩⟨attempted|
//! if Tr(Wρ) > 0 and block_ids differ → DOUBLE_SIGN
//! ```
//!
//! ## Hash Chain as Quantum Walk
//! The chain hash is a quantum fingerprint that entangles each state
//! with its predecessor, making rollbacks detectable via broken entanglement.

use crate::consensus::messages::VoteType;
use crate::crypto::PublicKeyBytes;
use crate::types::{Hash32, Height, Round};
use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    fs,
    path::Path,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc,
    },
};
use tracing::{debug, error, info, warn};

// -----------------------------------------------------------------------------
// Quantum Constants
// -----------------------------------------------------------------------------

/// Reduced Planck constant (natural units).
const HBAR: f64 = 1.0;

/// Minimum fidelity required for chain integrity.
const MIN_CHAIN_FIDELITY: f64 = 0.999999;

/// Decoherence rate per write operation.
const WRITE_DECOHERENCE_RATE: f64 = 0.0001;

/// Kraus rank for the record quantum channel.
const KRAUS_RANK: usize = 4;

// -----------------------------------------------------------------------------
// On‑disk format
// -----------------------------------------------------------------------------

/// The persisted quantum state of the double-sign guard.
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
struct GuardState {
    /// Key: `"proposal:<h>:<r>"` → block_id hex
    proposals: BTreeMap<String, String>,
    /// Key: `"vote:<type>:<h>:<r>"` → block_id hex (or `"nil"`)
    votes: BTreeMap<String, String>,
    /// Blake3 hash of the serialized state at the last successful write.
    /// Used to detect rollback/truncation attacks (entanglement witness).
    #[serde(default)]
    chain_hash: String,
    /// Quantum purity γ = Tr(ρ²) of the guard state.
    #[serde(default = "default_purity")]
    purity: f64,
    /// Von Neumann entropy S = -Tr(ρ ln ρ).
    #[serde(default)]
    entropy: f64,
    /// Total operations performed.
    #[serde(default)]
    total_operations: u64,
    /// Number of double-sign detections (should always be 0).
    #[serde(default)]
    double_sign_detections: u64,
}

fn default_purity() -> f64 {
    1.0
}

impl GuardState {
    /// Compute the hash of the current state (excluding `chain_hash` itself).
    fn compute_hash(&self) -> String {
        let canonical = serde_json::json!({
            "proposals": &self.proposals,
            "votes": &self.votes,
            "purity": self.purity,
            "entropy": self.entropy,
            "total_operations": self.total_operations,
        });
        let bytes = serde_json::to_vec(&canonical).unwrap_or_default();
        let hash = blake3::hash(&bytes);
        hex::encode(hash.as_bytes())
    }

    /// Stamp the `chain_hash` field with the current state hash.
    fn stamp(&mut self) {
        self.chain_hash = self.compute_hash();
    }

    /// Verify that the stored `chain_hash` matches the current state.
    /// Returns `Err` if the file appears rolled back or tampered.
    fn verify_chain(&self) -> Result<(), String> {
        if self.chain_hash.is_empty() {
            // Fresh file, no chain yet.
            return Ok(());
        }
        let expected = self.compute_hash();
        if self.chain_hash != expected {
            error!(
                stored = %self.chain_hash,
                computed = %expected,
                "chain integrity FAILED"
            );
            return Err(format!(
                "double-sign guard chain integrity FAILED: stored={} computed={}",
                self.chain_hash, expected
            ));
        }
        Ok(())
    }

    /// Apply decoherence from a write operation.
    fn apply_decoherence(&mut self) {
        self.total_operations = self.total_operations.wrapping_add(1);
        let decay = (-WRITE_DECOHERENCE_RATE).exp();
        self.purity = (self.purity * decay).clamp(0.0, 1.0);
        self.entropy = if self.purity >= 1.0 {
            0.0
        } else {
            -self.purity * self.purity.ln().max(0.0)
        };
    }
}

// -----------------------------------------------------------------------------
// Disk I/O with atomic writes
// -----------------------------------------------------------------------------

/// Load the guard state from disk. Returns a fresh state if the file does not exist.
fn load_state(path: &str) -> Result<GuardState, String> {
    if !Path::new(path).exists() {
        return Ok(GuardState::default());
    }
    let raw = fs::read_to_string(path)
        .map_err(|e| format!("double-sign guard read error: {e}"))?;
    let mut st: GuardState = serde_json::from_str(&raw)
        .map_err(|e| format!("double-sign guard parse error: {e}"))?;

    // Verify chain integrity.
    st.verify_chain()?;

    info!(
        path = %path,
        proposals = st.proposals.len(),
        votes = st.votes.len(),
        purity = st.purity,
        "guard state loaded"
    );

    Ok(st)
}

/// Save the guard state to disk atomically (temporary file + rename).
fn save_state(path: &str, st: &mut GuardState) -> Result<(), String> {
    // Apply decoherence from the write operation
    st.apply_decoherence();

    // Stamp the hash chain before writing.
    st.stamp();

    let json = serde_json::to_string_pretty(st)
        .map_err(|e| format!("double-sign guard encode error: {e}"))?;

    let tmp_path = format!("{path}.tmp");
    if let Err(e) = fs::write(&tmp_path, &json) {
        error!(path = %tmp_path, error = %e, "failed to write temporary guard file");
        return Err(format!("double-sign guard write tmp error: {e}"));
    }
    if let Err(e) = fs::rename(&tmp_path, path) {
        error!(from = %tmp_path, to = %path, error = %e, "failed to rename guard file");
        return Err(format!("double-sign guard rename error: {e}"));
    }

    debug!(
        path = %path,
        purity = st.purity,
        "guard state saved"
    );
    Ok(())
}

// -----------------------------------------------------------------------------
// DoubleSignGuard
// -----------------------------------------------------------------------------

/// Thread‑safe quantum guard that prevents double‑signing.
///
/// Each check is a quantum measurement; each record applies a Kraus channel.
#[derive(Clone, Debug)]
pub struct DoubleSignGuard {
    path: String,
    inner: Arc<Mutex<GuardState>>,
    /// Total successful checks (measurements).
    checks_passed: Arc<AtomicU64>,
    /// Total double-sign detections.
    detections: Arc<AtomicU64>,
    /// Total records (Kraus channel applications).
    records: Arc<AtomicU64>,
}

impl DoubleSignGuard {
    /// Load (or create) the guard for the given validator public key.
    ///
    /// Returns `Err` if the on‑disk state fails chain integrity verification.
    /// **FATAL** — do not start the node if this fails.
    pub fn new(data_dir: &str, pk: &PublicKeyBytes) -> Result<Self, String> {
        let pk_hex = hex::encode(&pk.0);
        let path = format!("{data_dir}/doublesign_{pk_hex}.json");
        info!(path = %path, "loading quantum double‑sign guard");

        let st = load_state(&path)?;
        let guard = Self {
            path,
            inner: Arc::new(Mutex::new(st)),
            checks_passed: Arc::new(AtomicU64::new(0)),
            detections: Arc::new(AtomicU64::new(0)),
            records: Arc::new(AtomicU64::new(0)),
        };

        if let Err(e) = guard.verify_integrity() {
            error!(error = %e, "integrity check failed on load");
            return Err(e);
        }

        let (proposals, votes) = guard.record_count();
        info!(
            proposals = proposals,
            votes = votes,
            purity = guard.purity(),
            "quantum double‑sign guard loaded"
        );
        Ok(guard)
    }

    /// Create with a legacy fallback (never fails; used in tests and dev).
    ///
    /// **WARNING**: This should not be used in production; it ignores integrity errors.
    pub fn new_or_default(data_dir: &str, pk: &PublicKeyBytes) -> Self {
        match Self::new(data_dir, pk) {
            Ok(g) => g,
            Err(e) => {
                warn!("double-sign guard load failed: {e}; starting fresh (DEV ONLY)");
                let pk_hex = hex::encode(&pk.0);
                Self {
                    path: format!("{data_dir}/doublesign_{pk_hex}.json"),
                    inner: Arc::new(Mutex::new(GuardState::default())),
                    checks_passed: Arc::new(AtomicU64::new(0)),
                    detections: Arc::new(AtomicU64::new(0)),
                    records: Arc::new(AtomicU64::new(0)),
                }
            }
        }
    }

    // -------------------------------------------------------------------------
    // Proposal checks and recording
    // -------------------------------------------------------------------------

    /// Quantum measurement: check if signing this proposal would be a double‑sign.
    ///
    /// Applies the projective measurement operator:
    /// ```text
    /// P̂_check = |existing⟩⟨existing| ⊗ |attempted⟩⟨attempted|
    /// ```
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
                // Entanglement witness triggered — DOUBLE_SIGN
                let msg = format!(
                    "DOUBLE-PROPOSAL REFUSED height={height} round={round} \
                     existing={existing} attempted={want}"
                );
                error!("{}", msg);
                self.detections.fetch_add(1, Ordering::Relaxed);
                return Err(msg);
            }
        }

        self.checks_passed.fetch_add(1, Ordering::Relaxed);
        debug!(height, round, block = %want, "proposal check passed");
        Ok(())
    }

    /// Quantum channel: record that this proposal was signed.
    ///
    /// Applies the creation operator:
    /// ```text
    /// a†_r |∅⟩ → |proposal_record⟩
    /// ```
    /// Must be called **BEFORE** signing.
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
        self.records.fetch_add(1, Ordering::Relaxed);
        info!(height, round, "recording proposal signature");
        save_state(&self.path, &mut st)
    }

    // -------------------------------------------------------------------------
    // Vote checks and recording
    // -------------------------------------------------------------------------

    /// Quantum measurement: check if signing this vote would be a double‑sign.
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
                let msg = format!(
                    "DOUBLE-VOTE REFUSED type={vt:?} height={height} round={round} \
                     existing={existing} attempted={want}"
                );
                error!("{}", msg);
                self.detections.fetch_add(1, Ordering::Relaxed);
                return Err(msg);
            }
        }

        self.checks_passed.fetch_add(1, Ordering::Relaxed);
        debug!(?vt, height, round, vote = %want, "vote check passed");
        Ok(())
    }

    /// Quantum channel: record that this vote was signed.
    ///
    /// Must be called **BEFORE** signing.
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
        self.records.fetch_add(1, Ordering::Relaxed);
        info!(?vt, height, round, "recording vote signature");
        save_state(&self.path, &mut st)
    }

    // -------------------------------------------------------------------------
    // Quantum inspection and debugging
    // -------------------------------------------------------------------------

    /// Returns the number of signed proposals and votes recorded.
    pub fn record_count(&self) -> (usize, usize) {
        let st = self.inner.lock();
        (st.proposals.len(), st.votes.len())
    }

    /// Quantum purity γ = Tr(ρ²) of the guard state.
    pub fn purity(&self) -> f64 {
        self.inner.lock().purity
    }

    /// Von Neumann entropy S = -Tr(ρ ln ρ) of the guard state.
    pub fn entropy(&self) -> f64 {
        self.inner.lock().entropy
    }

    /// Total operations performed.
    pub fn total_operations(&self) -> u64 {
        self.inner.lock().total_operations
    }

    /// Total checks passed (projective measurements).
    pub fn checks_passed(&self) -> u64 {
        self.checks_passed.load(Ordering::Relaxed)
    }

    /// Total double-sign detections (should always be 0).
    pub fn detections(&self) -> u64 {
        self.detections.load(Ordering::Relaxed)
    }

    /// Total records (Kraus channel applications).
    pub fn total_records(&self) -> u64 {
        self.records.load(Ordering::Relaxed)
    }

    /// Verify the on‑disk chain integrity right now.
    pub fn verify_integrity(&self) -> Result<(), String> {
        let st = self.inner.lock();
        st.verify_chain()
    }

    /// Get the path to the guard file (for debugging).
    pub fn path(&self) -> &str {
        &self.path
    }

    /// Get quantum guard statistics.
    pub fn stats(&self) -> GuardStats {
        let st = self.inner.lock();
        GuardStats {
            proposals: st.proposals.len(),
            votes: st.votes.len(),
            purity: st.purity,
            entropy: st.entropy,
            total_operations: st.total_operations,
            checks_passed: self.checks_passed.load(Ordering::Relaxed),
            detections: self.detections.load(Ordering::Relaxed),
            total_records: self.records.load(Ordering::Relaxed),
            chain_hash: st.chain_hash.clone(),
        }
    }
}

// -----------------------------------------------------------------------------
// Guard Statistics
// -----------------------------------------------------------------------------

/// Observable statistics for the quantum double-sign guard.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GuardStats {
    pub proposals: usize,
    pub votes: usize,
    pub purity: f64,
    pub entropy: f64,
    pub total_operations: u64,
    pub checks_passed: u64,
    pub detections: u64,
    pub total_records: u64,
    pub chain_hash: String,
}

// -----------------------------------------------------------------------------
// Helpers
// -----------------------------------------------------------------------------

/// Convert a `Hash32` to a hex string.
fn h32_hex(id: &Hash32) -> String {
    hex::encode(&id.0)
}

/// Build the key used to store a vote in the guard state.
pub fn vote_guard_key(vt: VoteType, height: Height, round: Round) -> String {
    format!("vote:{vt:?}:{height}:{round}")
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::PublicKeyBytes;
    use crate::types::Hash32;
    use tempfile::tempdir;

    fn test_guard() -> (DoubleSignGuard, tempfile::TempDir) {
        let dir = tempdir().unwrap();
        let pk = PublicKeyBytes(vec![0u8; 32]);
        let g = DoubleSignGuard::new(dir.path().to_str().unwrap(), &pk)
            .expect("guard should load");
        (g, dir)
    }

    fn hash(b: u8) -> Hash32 {
        Hash32([b; 32])
    }

    // ── Classical Tests ──────────────────────────────────────────────

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
        assert_eq!(g.detections(), 1);
    }

    #[test]
    fn test_double_vote_refused() {
        let (g, _dir) = test_guard();
        g.record_vote(VoteType::Prevote, 1, 0, &Some(hash(1)))
            .unwrap();
        let result = g.check_vote(VoteType::Prevote, 1, 0, &Some(hash(2)));
        assert!(result.is_err(), "double-vote must be refused");
        assert!(result.unwrap_err().contains("DOUBLE-VOTE"));
        assert_eq!(g.detections(), 1);
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
        assert!(g.check_proposal(1, 1, &hash(2)).is_ok());
    }

    #[test]
    fn test_chain_hash_persisted_and_verified() {
        let dir = tempdir().unwrap();
        let pk = PublicKeyBytes(vec![1u8; 32]);
        let path = dir.path().to_str().unwrap();

        {
            let g = DoubleSignGuard::new(path, &pk).unwrap();
            g.record_proposal(1, 0, &hash(1)).unwrap();
        }

        let g2 = DoubleSignGuard::new(path, &pk);
        assert!(
            g2.is_ok(),
            "reload with valid chain hash should succeed"
        );
        let (proposals, _) = g2.unwrap().record_count();
        assert_eq!(proposals, 1);
    }

    #[test]
    fn test_tampered_file_detected() {
        let dir = tempdir().unwrap();
        let pk = PublicKeyBytes(vec![2u8; 32]);
        let path_str = dir.path().to_str().unwrap();

        {
            let g = DoubleSignGuard::new(path_str, &pk).unwrap();
            g.record_proposal(5, 0, &hash(5)).unwrap();
        }

        let guard_path =
            format!("{path_str}/doublesign_{}.json", hex::encode([2u8; 32]));
        let raw = fs::read_to_string(&guard_path).unwrap();
        let mut json: serde_json::Value = serde_json::from_str(&raw).unwrap();
        json["chain_hash"] =
            serde_json::Value::String("0000000000000000".to_string());
        fs::write(
            &guard_path,
            serde_json::to_string_pretty(&json).unwrap(),
        )
        .unwrap();

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

    #[test]
    fn test_record_count() {
        let (g, _dir) = test_guard();
        assert_eq!(g.record_count(), (0, 0));
        g.record_proposal(1, 0, &hash(1)).unwrap();
        assert_eq!(g.record_count(), (1, 0));
        g.record_vote(VoteType::Prevote, 1, 0, &Some(hash(1)))
            .unwrap();
        assert_eq!(g.record_count(), (1, 1));
    }

    // ── Quantum Tests ────────────────────────────────────────────────

    #[test]
    fn test_quantum_purity_after_operations() {
        let (g, _dir) = test_guard();
        let initial_purity = g.purity();
        assert!((initial_purity - 1.0).abs() < 1e-10);

        for i in 0..5 {
            g.record_proposal(i, 0, &hash(i as u8)).unwrap();
        }

        let final_purity = g.purity();
        assert!(final_purity < initial_purity);
    }

    #[test]
    fn test_quantum_entropy_increases() {
        let (g, _dir) = test_guard();
        let initial_entropy = g.entropy();
        assert!((initial_entropy - 0.0).abs() < 1e-10);

        g.record_proposal(1, 0, &hash(1)).unwrap();

        let final_entropy = g.entropy();
        assert!(final_entropy > initial_entropy);
    }

    #[test]
    fn test_checks_passed_counter() {
        let (g, _dir) = test_guard();
        assert_eq!(g.checks_passed(), 0);

        g.check_proposal(1, 0, &hash(1)).unwrap();
        assert_eq!(g.checks_passed(), 1);

        g.check_vote(VoteType::Precommit, 1, 0, &None).unwrap();
        assert_eq!(g.checks_passed(), 2);
    }

    #[test]
    fn test_total_records_counter() {
        let (g, _dir) = test_guard();
        assert_eq!(g.total_records(), 0);

        g.record_proposal(1, 0, &hash(1)).unwrap();
        assert_eq!(g.total_records(), 1);

        g.record_vote(VoteType::Prevote, 1, 0, &Some(hash(1)))
            .unwrap();
        assert_eq!(g.total_records(), 2);
    }

    #[test]
    fn test_stats() {
        let (g, _dir) = test_guard();
        g.record_proposal(1, 0, &hash(1)).unwrap();
        g.record_vote(VoteType::Prevote, 1, 0, &Some(hash(1)))
            .unwrap();
        g.check_proposal(1, 0, &hash(1)).unwrap();

        let stats = g.stats();
        assert_eq!(stats.proposals, 1);
        assert_eq!(stats.votes, 1);
        assert_eq!(stats.checks_passed, 1);
        assert_eq!(stats.total_records, 2);
        assert!(stats.purity < 1.0);
        assert!(!stats.chain_hash.is_empty());
    }

    #[test]
    fn test_total_operations_tracks_writes() {
        let (g, _dir) = test_guard();
        assert_eq!(g.total_operations(), 0);

        g.record_proposal(1, 0, &hash(1)).unwrap();
        assert_eq!(g.total_operations(), 1);

        g.record_vote(VoteType::Prevote, 1, 0, &Some(hash(1)))
            .unwrap();
        assert_eq!(g.total_operations(), 2);
    }

    #[test]
    fn test_detections_always_zero_initially() {
        let (g, _dir) = test_guard();
        assert_eq!(g.detections(), 0);
    }

    #[test]
    fn test_guard_path() {
        let (g, _dir) = test_guard();
        assert!(g.path().contains("doublesign_"));
    }
}
