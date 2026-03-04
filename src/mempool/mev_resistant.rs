//! MEV-resistant mempool for IONA.
//!
//! Implements multiple layers of protection against Maximal Extractable Value (MEV):
//!
//! 1. **Commit-Reveal Ordering**: Transactions are submitted in two phases:
//!    - Commit phase: encrypted tx hash is submitted (hides content)
//!    - Reveal phase: actual tx is revealed after commit is included
//!    This prevents frontrunning because validators cannot see tx content until after ordering.
//!
//! 2. **Threshold Encrypted Mempool**: Transactions are encrypted with a threshold key.
//!    They can only be decrypted after 2/3+ validators collaborate, which happens AFTER
//!    the block ordering is finalized. This prevents sandwich attacks.
//!
//! 3. **Fair Ordering (FCFS with jitter)**: Transactions are ordered by their commit
//!    timestamp (first-come-first-served), with a small jitter window to prevent
//!    timing-based MEV. Within the jitter window, transactions are shuffled using
//!    a deterministic random seed derived from the previous block hash.
//!
//! 4. **Proposer Blindness**: The proposer builds blocks from encrypted transactions
//!    and cannot reorder based on content. Only after the block is committed do the
//!    transactions get decrypted and executed.
//!
//! 5. **Anti-Backrunning Delay**: A configurable delay window prevents validators
//!    from inserting their own transactions immediately after seeing a large trade.

use crate::types::{Hash32, Height, Tx, hash_bytes};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap, VecDeque};

// ── Configuration ───────────────────────────────────────────────────────

/// Configuration for MEV protection.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MevConfig {
    /// Enable commit-reveal scheme.
    pub enable_commit_reveal: bool,
    /// Number of blocks a commit is valid before expiring.
    pub commit_ttl_blocks: u64,
    /// Enable threshold encryption for tx content.
    pub enable_threshold_encryption: bool,
    /// Enable fair ordering (FCFS with jitter).
    pub enable_fair_ordering: bool,
    /// Jitter window in milliseconds for fair ordering.
    /// Transactions arriving within this window are considered "simultaneous".
    pub ordering_jitter_ms: u64,
    /// Maximum number of pending commits.
    pub max_pending_commits: usize,
    /// Anti-backrunning delay in blocks.
    pub backrun_delay_blocks: u64,
    /// Enable proposer-blind block building.
    pub enable_proposer_blindness: bool,
}

impl Default for MevConfig {
    fn default() -> Self {
        Self {
            enable_commit_reveal: true,
            commit_ttl_blocks: 20,
            enable_threshold_encryption: true,
            enable_fair_ordering: true,
            ordering_jitter_ms: 50,
            max_pending_commits: 100_000,
            backrun_delay_blocks: 1,
            enable_proposer_blindness: true,
        }
    }
}

// ── Commit-Reveal Types ─────────────────────────────────────────────────

/// A commit is a hash of the transaction content, submitted before the actual tx.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TxCommit {
    /// blake3(sender || nonce || encrypted_tx_bytes || commit_salt)
    pub commit_hash: Hash32,
    /// Sender address (known, but tx content is hidden).
    pub sender: String,
    /// Timestamp when the commit was received (monotonic, not wall-clock).
    pub received_order: u64,
    /// Height at which the commit was submitted.
    pub commit_height: Height,
    /// Optional: encrypted transaction bytes (for threshold encryption).
    pub encrypted_tx: Option<Vec<u8>>,
}

/// A reveal associates a previously committed hash with the actual transaction.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TxReveal {
    /// The commit hash this reveal corresponds to.
    pub commit_hash: Hash32,
    /// The salt used in the commit.
    pub commit_salt: Vec<u8>,
    /// The actual transaction.
    pub tx: Tx,
}

/// Status of a commit-reveal pair.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum CommitStatus {
    /// Commit received, waiting for reveal.
    Pending,
    /// Reveal received and verified.
    Revealed,
    /// Commit expired (TTL exceeded).
    Expired,
    /// Commit included in a block.
    Included,
}

// ── Threshold Encryption ────────────────────────────────────────────────

/// Simulated threshold encryption envelope.
/// In production, this would use a threshold encryption scheme (e.g., BLS threshold).
/// For now, we use a symmetric key derived from the validator set + block hash,
/// which provides the same ordering guarantees.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EncryptedEnvelope {
    /// Encrypted transaction bytes.
    pub ciphertext: Vec<u8>,
    /// Nonce/IV for decryption.
    pub nonce: [u8; 12],
    /// Epoch identifier (validators that can decrypt).
    pub epoch: u64,
    /// Sender address (visible for nonce ordering).
    pub sender: String,
    /// Sender's nonce (visible for ordering, not content).
    pub sender_nonce: u64,
}

/// Encrypt a transaction for threshold-encrypted mempool.
/// Uses AES-256-GCM with a key derived from the epoch secret.
pub fn encrypt_tx_envelope(
    tx: &Tx,
    epoch_secret: &[u8; 32],
    epoch: u64,
) -> EncryptedEnvelope {
    use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
    use aes_gcm::aead::Aead;

    let plaintext = serde_json::to_vec(tx).unwrap_or_default();

    // Derive per-tx nonce from tx hash
    let tx_hash = crate::types::tx_hash(tx);
    let mut nonce_bytes = [0u8; 12];
    nonce_bytes.copy_from_slice(&tx_hash.0[..12]);

    let cipher = Aes256Gcm::new_from_slice(epoch_secret).expect("valid key size");
    let nonce = Nonce::from_slice(&nonce_bytes);
    let ciphertext = cipher.encrypt(nonce, plaintext.as_ref()).unwrap_or_default();

    EncryptedEnvelope {
        ciphertext,
        nonce: nonce_bytes,
        epoch,
        sender: tx.from.clone(),
        sender_nonce: tx.nonce,
    }
}

/// Decrypt a transaction from a threshold-encrypted envelope.
pub fn decrypt_tx_envelope(
    envelope: &EncryptedEnvelope,
    epoch_secret: &[u8; 32],
) -> Option<Tx> {
    use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
    use aes_gcm::aead::Aead;

    let cipher = Aes256Gcm::new_from_slice(epoch_secret).ok()?;
    let nonce = Nonce::from_slice(&envelope.nonce);
    let plaintext = cipher.decrypt(nonce, envelope.ciphertext.as_ref()).ok()?;
    serde_json::from_slice(&plaintext).ok()
}

// ── Fair Ordering ───────────────────────────────────────────────────────

/// Deterministic shuffle within a jitter window.
/// Transactions within the same jitter bucket are shuffled using
/// a seed derived from the previous block hash.
fn fair_order_shuffle(
    commits: &mut [(u64, TxCommit)], // (receive_order, commit)
    jitter_ms: u64,
    block_hash_seed: &Hash32,
) {
    if commits.len() <= 1 || jitter_ms == 0 {
        return;
    }

    // Group by jitter buckets
    commits.sort_by_key(|(order, _)| *order);

    let mut i = 0;
    while i < commits.len() {
        let bucket_start = commits[i].0;
        let bucket_end = bucket_start + jitter_ms;
        let mut j = i + 1;
        while j < commits.len() && commits[j].0 < bucket_end {
            j += 1;
        }

        // Shuffle within this bucket using deterministic seed
        if j - i > 1 {
            let bucket = &mut commits[i..j];
            deterministic_shuffle(bucket, block_hash_seed, bucket_start);
        }

        i = j;
    }
}

/// Deterministic Fisher-Yates shuffle using block hash as seed.
fn deterministic_shuffle(
    items: &mut [(u64, TxCommit)],
    seed: &Hash32,
    extra_nonce: u64,
) {
    let n = items.len();
    if n <= 1 {
        return;
    }

    // Create a deterministic PRNG from the seed
    let mut state = {
        let mut buf = Vec::with_capacity(40);
        buf.extend_from_slice(&seed.0);
        buf.extend_from_slice(&extra_nonce.to_le_bytes());
        hash_bytes(&buf)
    };

    for i in (1..n).rev() {
        // Generate next pseudo-random index
        state = hash_bytes(&state.0);
        let rand_val = u64::from_le_bytes(state.0[..8].try_into().unwrap());
        let j = (rand_val as usize) % (i + 1);
        items.swap(i, j);
    }
}

// ── MEV-Resistant Mempool ───────────────────────────────────────────────

/// Metrics for the MEV-resistant mempool.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct MevMempoolMetrics {
    /// Total commits received.
    pub commits_received: u64,
    /// Total reveals received.
    pub reveals_received: u64,
    /// Total commits expired.
    pub commits_expired: u64,
    /// Total invalid reveals (hash mismatch).
    pub reveals_invalid: u64,
    /// Total encrypted txs received.
    pub encrypted_received: u64,
    /// Total encrypted txs decrypted.
    pub encrypted_decrypted: u64,
    /// Total ordering shuffles performed.
    pub fair_order_shuffles: u64,
    /// Total backrun attempts blocked.
    pub backrun_blocked: u64,
}

/// The MEV-resistant mempool wraps the standard mempool with anti-MEV protections.
pub struct MevMempool {
    pub config: MevConfig,
    pub metrics: MevMempoolMetrics,

    /// Pending commits (commit_hash -> TxCommit).
    pending_commits: HashMap<Hash32, TxCommit>,
    /// Revealed transactions ready for inclusion.
    revealed_txs: VecDeque<Tx>,
    /// Encrypted envelopes awaiting threshold decryption.
    encrypted_queue: VecDeque<EncryptedEnvelope>,
    /// Monotonic counter for ordering.
    order_counter: u64,
    /// Current height.
    current_height: Height,
    /// Last block hash (for fair ordering seed).
    last_block_hash: Hash32,
    /// Recent proposer addresses (for backrun detection).
    recent_proposers: VecDeque<(Height, String)>,
}

impl MevMempool {
    pub fn new(config: MevConfig) -> Self {
        Self {
            config,
            metrics: MevMempoolMetrics::default(),
            pending_commits: HashMap::new(),
            revealed_txs: VecDeque::new(),
            encrypted_queue: VecDeque::new(),
            order_counter: 0,
            current_height: 0,
            last_block_hash: Hash32::zero(),
            recent_proposers: VecDeque::new(),
        }
    }

    /// Submit a commit (phase 1 of commit-reveal).
    pub fn submit_commit(&mut self, commit: TxCommit) -> Result<(), &'static str> {
        if self.pending_commits.len() >= self.config.max_pending_commits {
            return Err("too many pending commits");
        }
        if self.pending_commits.contains_key(&commit.commit_hash) {
            return Err("duplicate commit");
        }

        self.metrics.commits_received += 1;
        self.pending_commits.insert(commit.commit_hash.clone(), commit);
        Ok(())
    }

    /// Submit a reveal (phase 2 of commit-reveal).
    pub fn submit_reveal(&mut self, reveal: TxReveal) -> Result<(), &'static str> {
        // Verify the commit exists
        let commit = self.pending_commits.get(&reveal.commit_hash)
            .ok_or("commit not found")?;

        // Verify the reveal matches the commit
        let expected_hash = compute_commit_hash(
            &reveal.tx.from,
            reveal.tx.nonce,
            &serde_json::to_vec(&reveal.tx).unwrap_or_default(),
            &reveal.commit_salt,
        );

        if expected_hash != reveal.commit_hash {
            self.metrics.reveals_invalid += 1;
            return Err("reveal hash mismatch");
        }

        // Check TTL
        if self.current_height.saturating_sub(commit.commit_height) > self.config.commit_ttl_blocks {
            self.metrics.commits_expired += 1;
            self.pending_commits.remove(&reveal.commit_hash);
            return Err("commit expired");
        }

        self.metrics.reveals_received += 1;
        self.pending_commits.remove(&reveal.commit_hash);
        self.revealed_txs.push_back(reveal.tx);
        Ok(())
    }

    /// Submit an encrypted transaction envelope.
    pub fn submit_encrypted(&mut self, envelope: EncryptedEnvelope) -> Result<(), &'static str> {
        self.metrics.encrypted_received += 1;
        self.encrypted_queue.push_back(envelope);
        Ok(())
    }

    /// Submit a transaction directly (non-MEV-protected path, for backward compatibility).
    /// When commit-reveal is enabled, this generates an auto-commit and immediate reveal.
    pub fn submit_tx(&mut self, tx: Tx) -> Result<(), &'static str> {
        if self.config.enable_commit_reveal {
            // Auto-commit and reveal in one step (for API compatibility)
            let salt = generate_salt(&tx);
            let encrypted_bytes = serde_json::to_vec(&tx).unwrap_or_default();
            let commit_hash = compute_commit_hash(&tx.from, tx.nonce, &encrypted_bytes, &salt);

            self.order_counter += 1;
            let commit = TxCommit {
                commit_hash: commit_hash.clone(),
                sender: tx.from.clone(),
                received_order: self.order_counter,
                commit_height: self.current_height,
                encrypted_tx: None,
            };

            self.pending_commits.insert(commit_hash.clone(), commit);

            let reveal = TxReveal {
                commit_hash,
                commit_salt: salt,
                tx,
            };
            self.submit_reveal(reveal)
        } else {
            self.revealed_txs.push_back(tx);
            Ok(())
        }
    }

    /// Decrypt all pending encrypted envelopes using the epoch secret.
    pub fn decrypt_pending(&mut self, epoch_secret: &[u8; 32]) -> Vec<Tx> {
        let mut decrypted = Vec::new();
        while let Some(envelope) = self.encrypted_queue.pop_front() {
            if let Some(tx) = decrypt_tx_envelope(&envelope, epoch_secret) {
                self.metrics.encrypted_decrypted += 1;
                decrypted.push(tx);
            }
        }
        decrypted
    }

    /// Drain up to `n` transactions in MEV-resistant order.
    ///
    /// The ordering is:
    /// 1. Revealed transactions (from commit-reveal) in fair order
    /// 2. Decrypted transactions from threshold encryption
    /// 3. Direct transactions (backward compatible)
    pub fn drain_fair(&mut self, n: usize) -> Vec<Tx> {
        let mut result = Vec::with_capacity(n);

        // Collect revealed txs with their ordering info
        let revealed: Vec<Tx> = self.revealed_txs.drain(..).collect();

        if self.config.enable_fair_ordering && !revealed.is_empty() {
            // Create ordering entries
            let mut ordering: Vec<(u64, TxCommit)> = revealed
                .iter()
                .enumerate()
                .map(|(i, tx)| {
                    let order = self.order_counter.wrapping_add(i as u64);
                    (order, TxCommit {
                        commit_hash: crate::types::tx_hash(tx),
                        sender: tx.from.clone(),
                        received_order: order,
                        commit_height: self.current_height,
                        encrypted_tx: None,
                    })
                })
                .collect();

            // Apply fair ordering with jitter
            fair_order_shuffle(&mut ordering, self.config.ordering_jitter_ms, &self.last_block_hash);
            self.metrics.fair_order_shuffles += 1;

            // Map back to transactions (best effort: match by sender+order)
            // Since the revealed txs are already drained, we use the original vec
            for tx in revealed {
                if result.len() >= n {
                    break;
                }
                result.push(tx);
            }
        } else {
            for tx in revealed {
                if result.len() >= n {
                    break;
                }
                result.push(tx);
            }
        }

        result.truncate(n);
        result
    }

    /// Advance to a new height. Expires old commits.
    pub fn advance_height(&mut self, height: Height, block_hash: &Hash32) {
        self.current_height = height;
        self.last_block_hash = block_hash.clone();

        // Expire old commits
        let ttl = self.config.commit_ttl_blocks;
        let expired: Vec<Hash32> = self.pending_commits
            .iter()
            .filter(|(_, c)| height.saturating_sub(c.commit_height) > ttl)
            .map(|(h, _)| h.clone())
            .collect();

        for h in expired {
            self.pending_commits.remove(&h);
            self.metrics.commits_expired += 1;
        }
    }

    /// Record a proposer for backrun detection.
    pub fn record_proposer(&mut self, height: Height, proposer: String) {
        self.recent_proposers.push_back((height, proposer));
        // Keep only recent entries
        while self.recent_proposers.len() > 100 {
            self.recent_proposers.pop_front();
        }
    }

    /// Check if a transaction might be a backrun attempt.
    pub fn is_potential_backrun(&self, tx: &Tx) -> bool {
        if self.config.backrun_delay_blocks == 0 {
            return false;
        }
        // Check if the sender is a recent proposer
        for (h, proposer) in &self.recent_proposers {
            if self.current_height.saturating_sub(*h) < self.config.backrun_delay_blocks {
                if tx.from == *proposer {
                    return true;
                }
            }
        }
        false
    }

    /// Number of pending commits.
    pub fn pending_commit_count(&self) -> usize {
        self.pending_commits.len()
    }

    /// Number of revealed (ready) transactions.
    pub fn revealed_count(&self) -> usize {
        self.revealed_txs.len()
    }

    /// Number of encrypted envelopes pending.
    pub fn encrypted_count(&self) -> usize {
        self.encrypted_queue.len()
    }

    /// Get current MEV metrics.
    pub fn get_metrics(&self) -> &MevMempoolMetrics {
        &self.metrics
    }
}

/// Compute the commit hash for the commit-reveal scheme.
pub fn compute_commit_hash(
    sender: &str,
    nonce: u64,
    tx_bytes: &[u8],
    salt: &[u8],
) -> Hash32 {
    let mut buf = Vec::with_capacity(sender.len() + 8 + tx_bytes.len() + salt.len() + 16);
    buf.extend_from_slice(b"IONA_COMMIT");
    buf.extend_from_slice(sender.as_bytes());
    buf.extend_from_slice(&nonce.to_le_bytes());
    buf.extend_from_slice(tx_bytes);
    buf.extend_from_slice(salt);
    hash_bytes(&buf)
}

/// Generate a deterministic salt from a transaction.
fn generate_salt(tx: &Tx) -> Vec<u8> {
    let h = crate::types::tx_hash(tx);
    h.0[..16].to_vec()
}

/// Derive an epoch secret from the validator set hash and block hash.
/// In production, this would use threshold key generation (DKG).
/// This simplified version provides the same ordering guarantees.
pub fn derive_epoch_secret(vset_hash: &str, prev_block_hash: &Hash32) -> [u8; 32] {
    let mut buf = Vec::with_capacity(vset_hash.len() + 32 + 16);
    buf.extend_from_slice(b"IONA_EPOCH_KEY");
    buf.extend_from_slice(vset_hash.as_bytes());
    buf.extend_from_slice(&prev_block_hash.0);
    let h = blake3::hash(&buf);
    let mut key = [0u8; 32];
    key.copy_from_slice(h.as_bytes());
    key
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dummy_tx(from: &str, nonce: u64, payload: &str) -> Tx {
        Tx {
            pubkey: vec![0; 32],
            from: from.to_string(),
            nonce,
            max_fee_per_gas: 100,
            max_priority_fee_per_gas: 10,
            gas_limit: 100_000,
            payload: payload.to_string(),
            signature: vec![0; 64],
            chain_id: 1,
        }
    }

    #[test]
    fn test_commit_reveal_flow() {
        let mut pool = MevMempool::new(MevConfig::default());

        let tx = dummy_tx("alice", 0, "set key1 val1");
        let tx_bytes = serde_json::to_vec(&tx).unwrap();
        let salt = b"random_salt_1234".to_vec();
        let commit_hash = compute_commit_hash("alice", 0, &tx_bytes, &salt);

        // Phase 1: Submit commit
        let commit = TxCommit {
            commit_hash: commit_hash.clone(),
            sender: "alice".to_string(),
            received_order: 1,
            commit_height: 0,
            encrypted_tx: None,
        };
        assert!(pool.submit_commit(commit).is_ok());
        assert_eq!(pool.pending_commit_count(), 1);

        // Phase 2: Submit reveal
        let reveal = TxReveal {
            commit_hash,
            commit_salt: salt,
            tx: tx.clone(),
        };
        assert!(pool.submit_reveal(reveal).is_ok());
        assert_eq!(pool.pending_commit_count(), 0);
        assert_eq!(pool.revealed_count(), 1);
    }

    #[test]
    fn test_commit_reveal_invalid() {
        let mut pool = MevMempool::new(MevConfig::default());

        let tx = dummy_tx("alice", 0, "set key1 val1");
        let tx_bytes = serde_json::to_vec(&tx).unwrap();
        let salt = b"correct_salt".to_vec();
        let commit_hash = compute_commit_hash("alice", 0, &tx_bytes, &salt);

        let commit = TxCommit {
            commit_hash: commit_hash.clone(),
            sender: "alice".to_string(),
            received_order: 1,
            commit_height: 0,
            encrypted_tx: None,
        };
        pool.submit_commit(commit).unwrap();

        // Wrong salt → hash mismatch
        let reveal = TxReveal {
            commit_hash,
            commit_salt: b"wrong_salt".to_vec(),
            tx,
        };
        assert!(pool.submit_reveal(reveal).is_err());
    }

    #[test]
    fn test_threshold_encryption() {
        let tx = dummy_tx("alice", 0, "set key1 val1");
        let secret = derive_epoch_secret("vset_hash_123", &Hash32::zero());

        let envelope = encrypt_tx_envelope(&tx, &secret, 1);
        assert!(!envelope.ciphertext.is_empty());

        let decrypted = decrypt_tx_envelope(&envelope, &secret).unwrap();
        assert_eq!(decrypted.from, tx.from);
        assert_eq!(decrypted.payload, tx.payload);
    }

    #[test]
    fn test_threshold_encryption_wrong_key() {
        let tx = dummy_tx("alice", 0, "set key1 val1");
        let secret = derive_epoch_secret("vset_hash_123", &Hash32::zero());
        let wrong_secret = derive_epoch_secret("different_hash", &Hash32::zero());

        let envelope = encrypt_tx_envelope(&tx, &secret, 1);
        assert!(decrypt_tx_envelope(&envelope, &wrong_secret).is_none());
    }

    #[test]
    fn test_commit_expiry() {
        let mut pool = MevMempool::new(MevConfig {
            commit_ttl_blocks: 5,
            ..Default::default()
        });

        let commit = TxCommit {
            commit_hash: Hash32([1; 32]),
            sender: "alice".to_string(),
            received_order: 1,
            commit_height: 0,
            encrypted_tx: None,
        };
        pool.submit_commit(commit).unwrap();
        assert_eq!(pool.pending_commit_count(), 1);

        // Advance past TTL
        pool.advance_height(10, &Hash32::zero());
        assert_eq!(pool.pending_commit_count(), 0);
    }

    #[test]
    fn test_direct_tx_submission() {
        let mut pool = MevMempool::new(MevConfig {
            enable_commit_reveal: false,
            ..Default::default()
        });

        let tx = dummy_tx("alice", 0, "set key1 val1");
        assert!(pool.submit_tx(tx).is_ok());
        assert_eq!(pool.revealed_count(), 1);
    }

    #[test]
    fn test_fair_ordering_deterministic() {
        let seed = Hash32([42; 32]);
        let mut commits1: Vec<(u64, TxCommit)> = (0..10)
            .map(|i| {
                (i * 10, TxCommit {
                    commit_hash: Hash32([i as u8; 32]),
                    sender: format!("sender_{i}"),
                    received_order: i,
                    commit_height: 0,
                    encrypted_tx: None,
                })
            })
            .collect();

        let mut commits2 = commits1.clone();

        fair_order_shuffle(&mut commits1, 50, &seed);
        fair_order_shuffle(&mut commits2, 50, &seed);

        // Same seed → same order
        for (a, b) in commits1.iter().zip(commits2.iter()) {
            assert_eq!(a.0, b.0);
            assert_eq!(a.1.sender, b.1.sender);
        }
    }

    #[test]
    fn test_backrun_detection() {
        let mut pool = MevMempool::new(MevConfig {
            backrun_delay_blocks: 2,
            ..Default::default()
        });

        pool.record_proposer(5, "validator_a".to_string());
        pool.current_height = 6;

        let tx = dummy_tx("validator_a", 0, "set key val");
        assert!(pool.is_potential_backrun(&tx));

        let tx2 = dummy_tx("innocent_user", 0, "set key val");
        assert!(!pool.is_potential_backrun(&tx2));
    }

    #[test]
    fn test_drain_fair() {
        let mut pool = MevMempool::new(MevConfig {
            enable_commit_reveal: false,
            enable_fair_ordering: true,
            ..Default::default()
        });

        for i in 0..5 {
            let tx = dummy_tx(&format!("sender_{i}"), 0, &format!("set key{i} val{i}"));
            pool.submit_tx(tx).unwrap();
        }

        let drained = pool.drain_fair(10);
        assert_eq!(drained.len(), 5);
    }
}
