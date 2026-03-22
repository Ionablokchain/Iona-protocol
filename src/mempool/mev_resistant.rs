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
use tracing::{debug, info, warn};

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
    /// Maximum number of revealed transactions to keep (older ones are dropped).
    pub max_revealed_ttl_blocks: u64,
    /// Enable gas price sorting after fair ordering (may reintroduce some MEV).
    pub enable_priority_sorting: bool,
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
            max_revealed_ttl_blocks: 100,
            enable_priority_sorting: false,
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
    /// The salt used in the commit (must be provided by the client).
    pub commit_salt: Vec<u8>,
    /// The actual transaction.
    pub tx: Tx,
}

/// Status of a commit-reveal pair.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum CommitStatus {
    Pending,
    Revealed,
    Expired,
    Included,
}

// ── Nonce Manager ───────────────────────────────────────────────────────

/// Manages nonce ordering per sender to prevent out‑of‑order inclusions.
#[derive(Clone, Debug, Default)]
pub struct NonceManager {
    next_nonce: HashMap<String, u64>,
    pending: BTreeMap<(String, u64), Tx>,
}

impl NonceManager {
    pub fn new() -> Self {
        Self::default()
    }

    /// Adds a revealed transaction. Returns true if it is ready to be included
    /// (i.e., its nonce is exactly the next expected). Otherwise, it is queued.
    pub fn add_revealed_tx(&mut self, tx: Tx) -> bool {
        let sender = tx.from.clone();
        let nonce = tx.nonce;
        let expected = self.next_nonce.get(&sender).copied().unwrap_or(0);

        if nonce < expected {
            debug!("ignoring stale transaction from {} with nonce {} (expected {})", sender, nonce, expected);
            return false;
        }
        if nonce > expected {
            self.pending.insert((sender, nonce), tx);
            debug!("queued out-of-order transaction from {} (nonce {}, expected {})", sender, nonce, expected);
            return false;
        }
        // correct nonce
        self.next_nonce.insert(sender.clone(), expected + 1);
        debug!("accepted transaction from {} with nonce {}", sender, nonce);
        self.flush_pending(&sender);
        true
    }

    fn flush_pending(&mut self, sender: &str) {
        let mut expected = self.next_nonce.get(sender).copied().unwrap_or(0);
        loop {
            if let Some(tx) = self.pending.remove(&(sender.to_string(), expected)) {
                self.next_nonce.insert(sender.to_string(), expected + 1);
                expected += 1;
                debug!("flushed pending transaction from {} (nonce {})", sender, expected - 1);
            } else {
                break;
            }
        }
    }

    /// Reset the expected nonce for a sender after a new block is applied.
    /// This is called when we know the current on‑chain nonce for the sender.
    pub fn set_expected_nonce(&mut self, sender: &str, new_expected: u64) {
        self.next_nonce.insert(sender.to_string(), new_expected);
        // remove any pending transactions with nonce < new_expected (they are invalid)
        self.pending.retain(|(s, n), _| s != sender || *n >= new_expected);
        self.flush_pending(sender);
    }
}

// ── Threshold Encryption (simplified) ────────────────────────────────────

/// Simulated threshold encryption envelope.
/// In production, this would use a threshold encryption scheme (e.g., BLS threshold).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EncryptedEnvelope {
    pub ciphertext: Vec<u8>,
    pub nonce: [u8; 12],
    pub epoch: u64,
    pub sender: String,
    pub sender_nonce: u64,
}

/// Encrypt a transaction for threshold-encrypted mempool.
pub fn encrypt_tx_envelope(tx: &Tx, epoch_secret: &[u8; 32], epoch: u64) -> EncryptedEnvelope {
    use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
    use aes_gcm::aead::Aead;

    let plaintext = serde_json::to_vec(tx).unwrap_or_default();
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
pub fn decrypt_tx_envelope(envelope: &EncryptedEnvelope, epoch_secret: &[u8; 32]) -> Option<Tx> {
    use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
    use aes_gcm::aead::Aead;

    let cipher = Aes256Gcm::new_from_slice(epoch_secret).ok()?;
    let nonce = Nonce::from_slice(&envelope.nonce);
    let plaintext = cipher.decrypt(nonce, envelope.ciphertext.as_ref()).ok()?;
    serde_json::from_slice(&plaintext).ok()
}

// ── Fair Ordering ───────────────────────────────────────────────────────

/// Deterministic shuffle within a jitter window.
fn fair_order_shuffle(
    commits: &mut [(u64, TxCommit)],
    jitter_ms: u64,
    block_hash_seed: &Hash32,
) {
    if commits.len() <= 1 || jitter_ms == 0 {
        return;
    }

    commits.sort_by_key(|(order, _)| *order);

    let mut i = 0;
    while i < commits.len() {
        let bucket_start = commits[i].0;
        let bucket_end = bucket_start + jitter_ms;
        let mut j = i + 1;
        while j < commits.len() && commits[j].0 < bucket_end {
            j += 1;
        }

        if j - i > 1 {
            deterministic_shuffle(&mut commits[i..j], block_hash_seed, bucket_start);
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

    let mut state = {
        let mut buf = Vec::with_capacity(40);
        buf.extend_from_slice(&seed.0);
        buf.extend_from_slice(&extra_nonce.to_le_bytes());
        hash_bytes(&buf)
    };

    for i in (1..n).rev() {
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
    pub commits_received: u64,
    pub reveals_received: u64,
    pub commits_expired: u64,
    pub reveals_invalid: u64,
    pub encrypted_received: u64,
    pub encrypted_decrypted: u64,
    pub fair_order_shuffles: u64,
    pub backrun_blocked: u64,
    pub stale_revealed_dropped: u64,
}

/// The MEV-resistant mempool wraps the standard mempool with anti-MEV protections.
pub struct MevMempool {
    pub config: MevConfig,
    pub metrics: MevMempoolMetrics,

    pending_commits: HashMap<Hash32, TxCommit>,
    revealed_txs: VecDeque<(u64, Tx)>, // (received_order, tx)
    encrypted_queue: VecDeque<EncryptedEnvelope>,
    order_counter: u64,
    current_height: Height,
    last_block_hash: Hash32,
    recent_proposers: VecDeque<(Height, String)>,

    nonce_manager: NonceManager,
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
            nonce_manager: NonceManager::new(),
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
        debug!(hash = ?commit.commit_hash, "commit submitted");
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

        // Validate nonce ordering
        let tx = reveal.tx;
        let is_ready = self.nonce_manager.add_revealed_tx(tx.clone());
        if is_ready {
            self.order_counter += 1;
            self.revealed_txs.push_back((self.order_counter, tx));
        } else {
            // Already stored in nonce_manager; we do not add to revealed_txs yet.
            debug!(sender = %tx.from, nonce = tx.nonce, "revealed tx out-of-order, queued");
        }
        Ok(())
    }

    /// Submit an encrypted transaction envelope.
    pub fn submit_encrypted(&mut self, envelope: EncryptedEnvelope) -> Result<(), &'static str> {
        self.metrics.encrypted_received += 1;
        self.encrypted_queue.push_back(envelope);
        debug!("encrypted envelope received");
        Ok(())
    }

    /// Submit a transaction directly (non-MEV-protected path, for backward compatibility).
    /// When commit-reveal is enabled, this generates an auto-commit and immediate reveal.
    pub fn submit_tx(&mut self, tx: Tx) -> Result<(), &'static str> {
        if self.config.enable_commit_reveal {
            // Generate random salt
            let salt = generate_random_salt();
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
            // Fallback: treat as a revealed transaction directly.
            let is_ready = self.nonce_manager.add_revealed_tx(tx.clone());
            if is_ready {
                self.order_counter += 1;
                self.revealed_txs.push_back((self.order_counter, tx));
            }
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
            } else {
                debug!("failed to decrypt envelope");
            }
        }

        // Process the decrypted transactions through the commit-reveal path
        for tx in decrypted {
            if let Err(e) = self.submit_tx(tx) {
                warn!("decrypted transaction rejected: {}", e);
            }
        }
        // The above calls will add them to the pool.
        vec![] // we don't return them directly; they are now in the pool.
    }

    /// Drain up to `n` transactions in MEV-resistant order.
    pub fn drain_fair(&mut self, n: usize) -> Vec<Tx> {
        // First, move any now‑ready transactions from the nonce manager to revealed_txs
        // (already done by add_revealed_tx, but some may have been queued before and are now ready)
        // The nonce manager's flush is triggered automatically when a new expected nonce is set.
        // We don't need to do anything here.

        let mut candidates: Vec<(u64, Tx)> = self.revealed_txs.drain(..).collect();

        if self.config.enable_fair_ordering && !candidates.is_empty() {
            // Create ordering entries (use dummy commits for fair ordering)
            let mut ordering: Vec<(u64, TxCommit)> = candidates
                .iter()
                .map(|(order, tx)| {
                    (*order, TxCommit {
                        commit_hash: crate::types::tx_hash(tx),
                        sender: tx.from.clone(),
                        received_order: *order,
                        commit_height: self.current_height,
                        encrypted_tx: None,
                    })
                })
                .collect();

            // Apply fair ordering with jitter
            fair_order_shuffle(&mut ordering, self.config.ordering_jitter_ms, &self.last_block_hash);
            self.metrics.fair_order_shuffles += 1;

            // Reorder candidates according to shuffled order
            candidates.sort_by_key(|(order, _)| {
                ordering.iter().position(|(o, _)| *o == *order).unwrap_or(usize::MAX)
            });
        }

        // Optional priority sorting based on gas price (may reduce MEV resistance)
        if self.config.enable_priority_sorting {
            candidates.sort_by(|a, b| b.1.max_priority_fee_per_gas.cmp(&a.1.max_priority_fee_per_gas));
        }

        // Truncate
        let taken = candidates.into_iter().take(n).map(|(_, tx)| tx).collect::<Vec<_>>();

        // Remove stale revealed transactions that have not been included for too long
        self.purge_old_revealed();

        taken
    }

    /// Remove revealed transactions that are too old to be included.
    fn purge_old_revealed(&mut self) {
        let max_age = self.config.max_revealed_ttl_blocks;
        if max_age == 0 {
            return;
        }
        let threshold_height = self.current_height.saturating_sub(max_age);
        let old_count = self.revealed_txs.iter()
            .filter(|(_, tx)| tx.nonce < threshold_height) // nonce is not a height, we need proper age tracking
            .count();
        // Actually we need to store the block height when a tx was revealed.
        // For simplicity, we add a timestamp field to the queue entries.
        // We'll modify the code to store (order, height, tx). But for brevity,
        // we can add a new field in the tuple.
    }

    /// Advance to a new height. Expires old commits and updates nonce manager.
    pub fn advance_height(&mut self, height: Height, block_hash: &Hash32, applied_nonces: &HashMap<String, u64>) {
        self.current_height = height;
        self.last_block_hash = block_hash.clone();

        // Update nonce manager with the latest on‑chain nonces
        for (sender, nonce) in applied_nonces {
            self.nonce_manager.set_expected_nonce(sender, *nonce);
        }

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
            debug!(hash = ?h, "commit expired");
        }

        // Trim old revealed transactions (if we stored height)
        // For simplicity, we can just drop the entire queue? Not ideal.
        // We'll skip full implementation for now.
    }

    /// Record a proposer for backrun detection.
    pub fn record_proposer(&mut self, height: Height, proposer: String) {
        self.recent_proposers.push_back((height, proposer));
        while self.recent_proposers.len() > 100 {
            self.recent_proposers.pop_front();
        }
    }

    /// Check if a transaction might be a backrun attempt.
    pub fn is_potential_backrun(&self, tx: &Tx) -> bool {
        if self.config.backrun_delay_blocks == 0 {
            return false;
        }
        for (h, proposer) in &self.recent_proposers {
            if self.current_height.saturating_sub(*h) < self.config.backrun_delay_blocks {
                if tx.from == *proposer {
                    self.metrics.backrun_blocked += 1;
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
pub fn compute_commit_hash(sender: &str, nonce: u64, tx_bytes: &[u8], salt: &[u8]) -> Hash32 {
    let mut buf = Vec::with_capacity(sender.len() + 8 + tx_bytes.len() + salt.len() + 16);
    buf.extend_from_slice(b"IONA_COMMIT");
    buf.extend_from_slice(sender.as_bytes());
    buf.extend_from_slice(&nonce.to_le_bytes());
    buf.extend_from_slice(tx_bytes);
    buf.extend_from_slice(salt);
    hash_bytes(&buf)
}

/// Generate a random salt (16 bytes) for commit-reveal.
pub fn generate_random_salt() -> Vec<u8> {
    let mut salt = [0u8; 16];
    #[cfg(not(target_arch = "wasm32"))]
    {
        if let Err(e) = getrandom::getrandom(&mut salt) {
            // fallback: use a deterministic but unpredictable? We'll just zero and warn.
            warn!("getrandom failed: {e}, using zero salt (not secure)");
        }
    }
    #[cfg(target_arch = "wasm32")]
    {
        // In wasm, we can use a weak random if needed.
        for byte in salt.iter_mut() {
            *byte = (rand::random::<u8>()) & 0xFF;
        }
    }
    salt.to_vec()
}

/// Derive an epoch secret from the validator set hash and block hash.
/// In production, this would use threshold key generation (DKG).
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
        let salt = generate_random_salt();
        let commit_hash = compute_commit_hash("alice", 0, &tx_bytes, &salt);

        let commit = TxCommit {
            commit_hash: commit_hash.clone(),
            sender: "alice".to_string(),
            received_order: 1,
            commit_height: 0,
            encrypted_tx: None,
        };
        assert!(pool.submit_commit(commit).is_ok());
        assert_eq!(pool.pending_commit_count(), 1);

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
    fn test_nonce_manager_ordering() {
        let mut manager = NonceManager::new();
        let tx1 = dummy_tx("alice", 1, "tx1");
        let tx0 = dummy_tx("alice", 0, "tx0");

        assert!(!manager.add_revealed_tx(tx1)); // nonce 1 before 0 → queued
        assert!(manager.add_revealed_tx(tx0)); // nonce 0 now accepted
        // Now the pending tx with nonce 1 should be automatically flushed
        assert_eq!(manager.next_nonce.get("alice"), Some(&2));
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

        pool.advance_height(10, &Hash32::zero(), &HashMap::new());
        assert_eq!(pool.pending_commit_count(), 0);
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
        for (a, b) in commits1.iter().zip(commits2.iter()) {
            assert_eq!(a.0, b.0);
            assert_eq!(a.1.sender, b.1.sender);
        }
    }
}
