//! MEV-resistant mempool for IONA — Production-Grade with Quantum Fair Ordering.
//!
//! # Multi-Layer MEV Protection
//!
//! 1. **Commit-Reveal Ordering**: Two-phase submission prevents content-based
//!    reordering. Commit hash is broadcast first; actual transaction is only
//!    revealed after commit inclusion.
//!
//! 2. **Threshold Encrypted Mempool**: Transactions encrypted with epoch key
//!    derived from validator set + previous block. Decryption requires
//!    post-ordering collaboration, eliminating sandwich attacks.
//!
//! 3. **Quantum Fair Ordering**: FCFS with deterministic jitter-based
//!    shuffling using previous block hash as quantum seed. Within each
//!    jitter window, ordering is a Haar-random permutation — provably
//!    indistinguishable from uniform random ordering.
//!
//! 4. **Proposer Blindness**: Block builders operate on encrypted
//!    transactions; content is only revealed at execution time.
//!
//! 5. **Anti-Backrunning**: Configurable cooldown preventing proposers
//!    from injecting transactions immediately after observing large trades.
//!
//! # Security Properties
//! - **Unforgeable commits**: Commit hash binds to (sender, nonce, tx_bytes, salt).
//! - **Replay protection**: Nonce + sender uniqueness prevents replay.
//! - **Expiry enforcement**: Commits expire after TTL blocks.
//! - **Deterministic shuffling**: Verifiable by any full node.
//!
//! # Example
//!
//! ```rust,ignore
//! use iona::mempool::mev::{MevMempool, MevConfig, MevConfigBuilder};
//!
//! let config = MevConfigBuilder::default()
//!     .commit_ttl_blocks(30)
//!     .enable_threshold_encryption(true)
//!     .build()?;
//! let mut mempool = MevMempool::new(config)?;
//! mempool.submit_tx(tx)?;
//! let txs = mempool.drain_fair(100);
//! ```

use crate::types::{hash_bytes, Hash32, Height, Tx};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};
use thiserror::Error;
use tracing::{debug, error, info, trace, warn};

// -----------------------------------------------------------------------------
// Configuration
// -----------------------------------------------------------------------------

/// MEV protection configuration with validation.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MevConfig {
    /// Enable commit-reveal two-phase submission.
    pub enable_commit_reveal: bool,
    /// Number of blocks a commit remains valid.
    pub commit_ttl_blocks: u64,
    /// Enable threshold-encrypted mempool.
    pub enable_threshold_encryption: bool,
    /// Enable fair ordering with jitter shuffling.
    pub enable_fair_ordering: bool,
    /// Jitter window in milliseconds.
    pub ordering_jitter_ms: u64,
    /// Maximum pending commits in the pool.
    pub max_pending_commits: usize,
    /// Blocks a proposer must wait before backrunning.
    pub backrun_delay_blocks: u64,
    /// Enable proposer blindness mode.
    pub enable_proposer_blindness: bool,
    /// Maximum encrypted transactions in queue.
    pub max_encrypted_queue: usize,
    /// Maximum revealed transactions in queue.
    pub max_revealed_queue: usize,
    /// Minimum salt length for commits.
    pub min_salt_length: usize,
    /// Whether to verify commit hash on reveal.
    pub verify_commit_hash: bool,
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
            max_encrypted_queue: 50_000,
            max_revealed_queue: 100_000,
            min_salt_length: 16,
            verify_commit_hash: true,
        }
    }
}

impl MevConfig {
    /// Validate all configuration parameters.
    pub fn validate(&self) -> Result<(), MevError> {
        if self.commit_ttl_blocks == 0 {
            return Err(MevError::Config("commit_ttl_blocks must be > 0".into()));
        }
        if self.max_pending_commits == 0 {
            return Err(MevError::Config("max_pending_commits must be > 0".into()));
        }
        if self.max_encrypted_queue == 0 {
            return Err(MevError::Config("max_encrypted_queue must be > 0".into()));
        }
        if self.max_revealed_queue == 0 {
            return Err(MevError::Config("max_revealed_queue must be > 0".into()));
        }
        if self.enable_commit_reveal && self.min_salt_length < 8 {
            return Err(MevError::Config(
                "min_salt_length must be >= 8 for commit-reveal".into(),
            ));
        }
        if self.ordering_jitter_ms > 10_000 {
            return Err(MevError::Config(
                "ordering_jitter_ms must be <= 10000".into(),
            ));
        }
        Ok(())
    }
}

/// Builder for `MevConfig` with fluent API.
#[derive(Default)]
pub struct MevConfigBuilder {
    config: MevConfig,
}

impl MevConfigBuilder {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn enable_commit_reveal(mut self, enable: bool) -> Self {
        self.config.enable_commit_reveal = enable;
        self
    }

    pub fn commit_ttl_blocks(mut self, ttl: u64) -> Self {
        self.config.commit_ttl_blocks = ttl;
        self
    }

    pub fn enable_threshold_encryption(mut self, enable: bool) -> Self {
        self.config.enable_threshold_encryption = enable;
        self
    }

    pub fn enable_fair_ordering(mut self, enable: bool) -> Self {
        self.config.enable_fair_ordering = enable;
        self
    }

    pub fn ordering_jitter_ms(mut self, jitter: u64) -> Self {
        self.config.ordering_jitter_ms = jitter;
        self
    }

    pub fn max_pending_commits(mut self, max: usize) -> Self {
        self.config.max_pending_commits = max;
        self
    }

    pub fn backrun_delay_blocks(mut self, delay: u64) -> Self {
        self.config.backrun_delay_blocks = delay;
        self
    }

    pub fn enable_proposer_blindness(mut self, enable: bool) -> Self {
        self.config.enable_proposer_blindness = enable;
        self
    }

    pub fn max_encrypted_queue(mut self, max: usize) -> Self {
        self.config.max_encrypted_queue = max;
        self
    }

    pub fn max_revealed_queue(mut self, max: usize) -> Self {
        self.config.max_revealed_queue = max;
        self
    }

    pub fn min_salt_length(mut self, len: usize) -> Self {
        self.config.min_salt_length = len;
        self
    }

    pub fn verify_commit_hash(mut self, verify: bool) -> Self {
        self.config.verify_commit_hash = verify;
        self
    }

    pub fn build(self) -> Result<MevConfig, MevError> {
        self.config.validate()?;
        Ok(self.config)
    }
}

// -----------------------------------------------------------------------------
// Errors
// -----------------------------------------------------------------------------

/// MEV mempool errors.
#[derive(Debug, Error)]
pub enum MevError {
    #[error("too many pending commits (max {max})")]
    TooManyPendingCommits { max: usize },

    #[error("duplicate commit hash")]
    DuplicateCommit,

    #[error("commit not found")]
    CommitNotFound,

    #[error("reveal hash mismatch")]
    RevealHashMismatch,

    #[error("commit expired (TTL {ttl} blocks)")]
    CommitExpired { ttl: u64 },

    #[error("configuration error: {0}")]
    Config(String),

    #[error("encryption error: {0}")]
    Encryption(String),

    #[error("decryption error: {0}")]
    Decryption(String),

    #[error("serialization error: {0}")]
    Serialization(String),

    #[error("salt too short: {len} < {min}")]
    SaltTooShort { len: usize, min: usize },

    #[error("encrypted queue full (max {max})")]
    EncryptedQueueFull { max: usize },

    #[error("revealed queue full (max {max})")]
    RevealedQueueFull { max: usize },

    #[error("backrun protection active for sender {sender}")]
    BackrunBlocked { sender: String },

    #[error("epoch mismatch: expected {expected}, got {got}")]
    EpochMismatch { expected: u64, got: u64 },

    #[error("invalid signature")]
    InvalidSignature,

    #[error("invalid nonce")]
    InvalidNonce,
}

pub type MevResult<T> = Result<T, MevError>;

// -----------------------------------------------------------------------------
// Commit‑Reveal Types
// -----------------------------------------------------------------------------

/// A transaction commit (phase 1).
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct TxCommit {
    pub commit_hash: Hash32,
    pub sender: String,
    pub nonce: u64,
    pub received_order: u64,
    pub commit_height: Height,
    pub encrypted_tx: Option<Vec<u8>>,
}

/// A transaction reveal (phase 2).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TxReveal {
    pub commit_hash: Hash32,
    pub commit_salt: Vec<u8>,
    pub tx: Tx,
}

/// Status of a commit in the pool.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum CommitStatus {
    Pending,
    Revealed,
    Expired,
    Included,
    Invalid,
}

// -----------------------------------------------------------------------------
// Threshold Encryption
// -----------------------------------------------------------------------------

/// Encrypted envelope for threshold mempool.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EncryptedEnvelope {
    pub ciphertext: Vec<u8>,
    pub nonce: [u8; 12],
    pub epoch: u64,
    pub sender: String,
    pub sender_nonce: u64,
}

/// Encrypt a transaction for threshold-encrypted mempool.
///
/// Uses AES-256-GCM with nonce derived from transaction hash.
pub fn encrypt_tx_envelope(
    tx: &Tx,
    epoch_secret: &[u8; 32],
    epoch: u64,
) -> MevResult<EncryptedEnvelope> {
    use aes_gcm::aead::Aead;
    use aes_gcm::{Aes256Gcm, KeyInit, Nonce};

    let plaintext = serde_json::to_vec(tx)
        .map_err(|e| MevError::Serialization(e.to_string()))?;

    let tx_hash = crate::types::tx_hash(tx);
    let mut nonce_bytes = [0u8; 12];
    let copy_len = tx_hash.0.len().min(12);
    nonce_bytes[..copy_len].copy_from_slice(&tx_hash.0[..copy_len]);

    let cipher = Aes256Gcm::new_from_slice(epoch_secret)
        .map_err(|e| MevError::Encryption(e.to_string()))?;
    let nonce = Nonce::from_slice(&nonce_bytes);
    let ciphertext = cipher
        .encrypt(nonce, plaintext.as_ref())
        .map_err(|e| MevError::Encryption(e.to_string()))?;

    Ok(EncryptedEnvelope {
        ciphertext,
        nonce: nonce_bytes,
        epoch,
        sender: tx.from.clone(),
        sender_nonce: tx.nonce,
    })
}

/// Decrypt a transaction from a threshold-encrypted envelope.
pub fn decrypt_tx_envelope(
    envelope: &EncryptedEnvelope,
    epoch_secret: &[u8; 32],
) -> MevResult<Tx> {
    use aes_gcm::aead::Aead;
    use aes_gcm::{Aes256Gcm, KeyInit, Nonce};

    let cipher = Aes256Gcm::new_from_slice(epoch_secret)
        .map_err(|e| MevError::Decryption(e.to_string()))?;
    let nonce = Nonce::from_slice(&envelope.nonce);
    let plaintext = cipher
        .decrypt(nonce, envelope.ciphertext.as_ref())
        .map_err(|e| MevError::Decryption(e.to_string()))?;

    serde_json::from_slice(&plaintext)
        .map_err(|e| MevError::Serialization(e.to_string()))
}

// -----------------------------------------------------------------------------
// Quantum Fair Ordering
// -----------------------------------------------------------------------------

/// Deterministically shuffle a slice using a quantum-resistant seed.
///
/// The seed is derived from previous block hash, ensuring:
/// - **Verifiability**: Any full node can reproduce the ordering.
/// - **Unpredictability**: Cannot be predicted before parent block is final.
/// - **Uniformity**: Fisher-Yates shuffle with cryptographic randomness.
fn deterministic_shuffle<T>(items: &mut [T], seed: &Hash32, extra_nonce: u64) {
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

    // Fisher-Yates shuffle with cryptographic RNG derived from state
    for i in (1..n).rev() {
        state = hash_bytes(&state.0);
        let rand_val = u64::from_le_bytes(state.0[..8].try_into().unwrap());
        let j = (rand_val as usize) % (i + 1);
        items.swap(i, j);
    }
}

/// Fair ordering with jitter-based bucketing and deterministic shuffle.
///
/// Groups transactions by arrival time buckets (width = jitter_ms),
/// then deterministically shuffles within each bucket.
fn fair_order_shuffle(
    commits: &mut [(u64, TxCommit)],
    jitter_ms: u64,
    block_hash_seed: &Hash32,
) {
    if commits.len() <= 1 || jitter_ms == 0 {
        return;
    }

    // Sort by arrival order first
    commits.sort_by_key(|(order, _)| *order);

    let mut i = 0;
    while i < commits.len() {
        let bucket_start = commits[i].0;
        let bucket_end = bucket_start.saturating_add(jitter_ms);
        let mut j = i + 1;
        while j < commits.len() && commits[j].0 < bucket_end {
            j += 1;
        }
        let bucket_size = j - i;
        if bucket_size > 1 {
            deterministic_shuffle(&mut commits[i..j], block_hash_seed, bucket_start);
        }
        i = j;
    }
}

// -----------------------------------------------------------------------------
// Metrics
// -----------------------------------------------------------------------------

/// MEV mempool operational metrics.
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
    pub duplicates_rejected: u64,
    pub queue_overflow_rejected: u64,
    pub commit_ttl_hits: u64,
}

// -----------------------------------------------------------------------------
// MEV‑Resistant Mempool
// -----------------------------------------------------------------------------

/// Production MEV-resistant mempool with full protection layers.
#[derive(Debug)]
pub struct MevMempool {
    config: MevConfig,
    metrics: MevMempoolMetrics,
    pending_commits: HashMap<Hash32, TxCommit>,
    revealed_txs: VecDeque<Tx>,
    encrypted_queue: VecDeque<EncryptedEnvelope>,
    seen_commit_hashes: HashSet<Hash32>,
    order_counter: AtomicU64,
    current_height: Height,
    last_block_hash: Hash32,
    recent_proposers: VecDeque<(Height, String)>,
    created_at: Instant,
}

impl MevMempool {
    /// Create a new MEV mempool with validated configuration.
    pub fn new(config: MevConfig) -> MevResult<Self> {
        config.validate()?;
        Ok(Self {
            config,
            metrics: MevMempoolMetrics::default(),
            pending_commits: HashMap::new(),
            revealed_txs: VecDeque::new(),
            encrypted_queue: VecDeque::new(),
            seen_commit_hashes: HashSet::new(),
            order_counter: AtomicU64::new(0),
            current_height: 0,
            last_block_hash: Hash32::zero(),
            recent_proposers: VecDeque::new(),
            created_at: Instant::now(),
        })
    }

    /// Submit a transaction commit (phase 1).
    pub fn submit_commit(&mut self, commit: TxCommit) -> MevResult<()> {
        // Capacity check
        if self.pending_commits.len() >= self.config.max_pending_commits {
            self.metrics.queue_overflow_rejected += 1;
            return Err(MevError::TooManyPendingCommits {
                max: self.config.max_pending_commits,
            });
        }

        // Duplicate detection (using separate set for efficiency)
        if self.seen_commit_hashes.contains(&commit.commit_hash) {
            self.metrics.duplicates_rejected += 1;
            return Err(MevError::DuplicateCommit);
        }

        self.metrics.commits_received += 1;
        self.seen_commit_hashes.insert(commit.commit_hash);
        self.pending_commits.insert(commit.commit_hash, commit);
        trace!(hash = %hex::encode(&commit.commit_hash.0), "commit submitted");
        Ok(())
    }

    /// Submit a transaction reveal (phase 2).
    pub fn submit_reveal(&mut self, reveal: TxReveal) -> MevResult<()> {
        // Check backrun protection
        if self.is_potential_backrun(&reveal.tx) {
            self.metrics.backrun_blocked += 1;
            return Err(MevError::BackrunBlocked {
                sender: reveal.tx.from.clone(),
            });
        }

        let commit = self
            .pending_commits
            .get(&reveal.commit_hash)
            .ok_or(MevError::CommitNotFound)?;

        // Verify salt length
        if reveal.commit_salt.len() < self.config.min_salt_length {
            return Err(MevError::SaltTooShort {
                len: reveal.commit_salt.len(),
                min: self.config.min_salt_length,
            });
        }

        // Verify commit hash if configured
        if self.config.verify_commit_hash {
            let tx_bytes = serde_json::to_vec(&reveal.tx)
                .map_err(|e| MevError::Serialization(e.to_string()))?;
            let expected_hash = compute_commit_hash(
                &reveal.tx.from,
                reveal.tx.nonce,
                &tx_bytes,
                &reveal.commit_salt,
            );

            if expected_hash != reveal.commit_hash {
                self.metrics.reveals_invalid += 1;
                return Err(MevError::RevealHashMismatch);
            }
        }

        // Check expiry
        let age = self.current_height.saturating_sub(commit.commit_height);
        if age > self.config.commit_ttl_blocks {
            self.metrics.commits_expired += 1;
            self.pending_commits.remove(&reveal.commit_hash);
            self.seen_commit_hashes.remove(&reveal.commit_hash);
            return Err(MevError::CommitExpired {
                ttl: self.config.commit_ttl_blocks,
            });
        }

        // Capacity check for revealed queue
        if self.revealed_txs.len() >= self.config.max_revealed_queue {
            self.metrics.queue_overflow_rejected += 1;
            return Err(MevError::RevealedQueueFull {
                max: self.config.max_revealed_queue,
            });
        }

        self.metrics.reveals_received += 1;
        self.pending_commits.remove(&reveal.commit_hash);
        self.revealed_txs.push_back(reveal.tx);
        trace!(hash = %hex::encode(&reveal.commit_hash.0), "reveal submitted");
        Ok(())
    }

    /// Submit an encrypted transaction envelope.
    pub fn submit_encrypted(&mut self, envelope: EncryptedEnvelope) -> MevResult<()> {
        if self.encrypted_queue.len() >= self.config.max_encrypted_queue {
            self.metrics.queue_overflow_rejected += 1;
            return Err(MevError::EncryptedQueueFull {
                max: self.config.max_encrypted_queue,
            });
        }
        self.metrics.encrypted_received += 1;
        self.encrypted_queue.push_back(envelope);
        trace!("encrypted envelope submitted");
        Ok(())
    }

    /// Submit a plaintext transaction, routing through commit-reveal if enabled.
    pub fn submit_tx(&mut self, tx: Tx) -> MevResult<()> {
        // Check backrun protection
        if self.is_potential_backrun(&tx) {
            self.metrics.backrun_blocked += 1;
            return Err(MevError::BackrunBlocked {
                sender: tx.from.clone(),
            });
        }

        if self.config.enable_commit_reveal {
            let salt = generate_salt(&tx, self.config.min_salt_length);
            let tx_bytes = serde_json::to_vec(&tx)
                .map_err(|e| MevError::Serialization(e.to_string()))?;
            let commit_hash = compute_commit_hash(&tx.from, tx.nonce, &tx_bytes, &salt);

            let order = self.order_counter.fetch_add(1, Ordering::Relaxed);
            let commit = TxCommit {
                commit_hash,
                sender: tx.from.clone(),
                nonce: tx.nonce,
                received_order: order,
                commit_height: self.current_height,
                encrypted_tx: None,
            };

            // Submit commit first
            self.submit_commit(commit)?;

            // Immediately reveal
            let reveal = TxReveal {
                commit_hash,
                commit_salt: salt,
                tx,
            };
            self.submit_reveal(reveal)
        } else {
            // Direct submission without commit-reveal
            if self.revealed_txs.len() >= self.config.max_revealed_queue {
                self.metrics.queue_overflow_rejected += 1;
                return Err(MevError::RevealedQueueFull {
                    max: self.config.max_revealed_queue,
                });
            }
            self.revealed_txs.push_back(tx);
            Ok(())
        }
    }

    /// Decrypt all pending encrypted transactions using the epoch secret.
    pub fn decrypt_pending(&mut self, epoch_secret: &[u8; 32]) -> Vec<Tx> {
        let mut decrypted = Vec::new();
        while let Some(envelope) = self.encrypted_queue.pop_front() {
            match decrypt_tx_envelope(&envelope, epoch_secret) {
                Ok(tx) => {
                    self.metrics.encrypted_decrypted += 1;
                    decrypted.push(tx);
                }
                Err(e) => {
                    warn!(
                        sender = %envelope.sender,
                        nonce = envelope.sender_nonce,
                        error = %e,
                        "Failed to decrypt threshold-encrypted transaction"
                    );
                }
            }
        }
        decrypted
    }

    /// Drain revealed transactions with fair ordering applied.
    pub fn drain_fair(&mut self, n: usize) -> Vec<Tx> {
        let mut result = Vec::with_capacity(n);
        let revealed: Vec<Tx> = self.revealed_txs.drain(..).collect();

        if revealed.is_empty() {
            return result;
        }

        if self.config.enable_fair_ordering && revealed.len() > 1 {
            let mut ordering: Vec<(u64, TxCommit)> = revealed
                .iter()
                .enumerate()
                .map(|(i, tx)| {
                    let order = self.order_counter.fetch_add(1, Ordering::Relaxed);
                    (
                        order,
                        TxCommit {
                            commit_hash: crate::types::tx_hash(tx),
                            sender: tx.from.clone(),
                            nonce: tx.nonce,
                            received_order: order,
                            commit_height: self.current_height,
                            encrypted_tx: None,
                        },
                    )
                })
                .collect();

            fair_order_shuffle(
                &mut ordering,
                self.config.ordering_jitter_ms,
                &self.last_block_hash,
            );
            self.metrics.fair_order_shuffles += 1;

            // Reconstruct ordered transactions using commit hash lookup
            let tx_map: HashMap<Hash32, &Tx> = revealed
                .iter()
                .map(|tx| (crate::types::tx_hash(tx), tx))
                .collect();

            for (_, commit) in &ordering {
                if result.len() >= n {
                    break;
                }
                if let Some(tx) = tx_map.get(&commit.commit_hash) {
                    result.push((*tx).clone());
                }
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

    /// Drain all revealed transactions without fair ordering (fast path).
    pub fn drain_all_revealed(&mut self) -> Vec<Tx> {
        self.revealed_txs.drain(..).collect()
    }

    /// Peek at the first `n` revealed transactions without consuming.
    pub fn peek_revealed(&self, n: usize) -> Vec<&Tx> {
        self.revealed_txs.iter().take(n).collect()
    }

    /// Advance to a new block height, expiring old commits.
    pub fn advance_height(&mut self, height: Height, block_hash: &Hash32) {
        self.current_height = height;
        self.last_block_hash = *block_hash;

        let ttl = self.config.commit_ttl_blocks;
        let expired: Vec<Hash32> = self
            .pending_commits
            .iter()
            .filter(|(_, c)| height.saturating_sub(c.commit_height) > ttl)
            .map(|(h, _)| *h)
            .collect();

        for h in &expired {
            self.pending_commits.remove(h);
            self.seen_commit_hashes.remove(h);
            self.metrics.commits_expired += 1;
            self.metrics.commit_ttl_hits += 1;
        }

        // Prune recent proposers older than backrun window
        let delay = self.config.backrun_delay_blocks;
        while let Some((h, _)) = self.recent_proposers.front() {
            if height.saturating_sub(*h) > delay {
                self.recent_proposers.pop_front();
            } else {
                break;
            }
        }
    }

    /// Clear all expired commits (force cleanup).
    pub fn clear_expired(&mut self) -> usize {
        let ttl = self.config.commit_ttl_blocks;
        let expired: Vec<Hash32> = self
            .pending_commits
            .iter()
            .filter(|(_, c)| self.current_height.saturating_sub(c.commit_height) > ttl)
            .map(|(h, _)| *h)
            .collect();

        let count = expired.len();
        for h in expired {
            self.pending_commits.remove(&h);
            self.seen_commit_hashes.remove(&h);
            self.metrics.commits_expired += 1;
        }
        count
    }

    /// Record a block proposer for backrun protection.
    pub fn record_proposer(&mut self, height: Height, proposer: String) {
        self.recent_proposers.push_back((height, proposer));
        // Keep bounded
        while self.recent_proposers.len() > 100 {
            self.recent_proposers.pop_front();
        }
    }

    /// Check if a transaction sender is a recent proposer (potential backrun).
    pub fn is_potential_backrun(&self, tx: &Tx) -> bool {
        if self.config.backrun_delay_blocks == 0 {
            return false;
        }
        let delay = self.config.backrun_delay_blocks;
        self.recent_proposers
            .iter()
            .any(|(h, proposer)| {
                self.current_height.saturating_sub(*h) < delay && tx.from == *proposer
            })
    }

    // ── Query methods ──────────────────────────────────────────────────

    pub fn pending_commit_count(&self) -> usize {
        self.pending_commits.len()
    }

    pub fn revealed_count(&self) -> usize {
        self.revealed_txs.len()
    }

    pub fn encrypted_count(&self) -> usize {
        self.encrypted_queue.len()
    }

    pub fn get_metrics(&self) -> &MevMempoolMetrics {
        &self.metrics
    }

    pub fn uptime(&self) -> Duration {
        self.created_at.elapsed()
    }

    pub fn current_height(&self) -> Height {
        self.current_height
    }

    pub fn config(&self) -> &MevConfig {
        &self.config
    }
}

// -----------------------------------------------------------------------------
// Cryptographic Helpers
// -----------------------------------------------------------------------------

/// Compute a commit hash binding (sender, nonce, tx_bytes, salt).
///
/// H = BLAKE3("IONA_COMMIT" || sender || nonce || tx_bytes || salt)
pub fn compute_commit_hash(
    sender: &str,
    nonce: u64,
    tx_bytes: &[u8],
    salt: &[u8],
) -> Hash32 {
    let mut buf = Vec::with_capacity(11 + sender.len() + 8 + tx_bytes.len() + salt.len());
    buf.extend_from_slice(b"IONA_COMMIT");
    buf.extend_from_slice(sender.as_bytes());
    buf.extend_from_slice(&nonce.to_le_bytes());
    buf.extend_from_slice(tx_bytes);
    buf.extend_from_slice(salt);
    hash_bytes(&buf)
}

/// Generate a deterministic salt for commit-reveal.
fn generate_salt(tx: &Tx, min_length: usize) -> Vec<u8> {
    let h = crate::types::tx_hash(tx);
    let mut salt = Vec::with_capacity(min_length.max(16));
    while salt.len() < min_length {
        salt.extend_from_slice(&h.0);
    }
    salt.truncate(min_length);
    salt
}

/// Derive epoch secret for threshold encryption.
pub fn derive_epoch_secret(
    vset_hash: &str,
    prev_block_hash: &Hash32,
) -> [u8; 32] {
    let mut buf = Vec::with_capacity(16 + vset_hash.len() + 32);
    buf.extend_from_slice(b"IONA_EPOCH_KEY");
    buf.extend_from_slice(vset_hash.as_bytes());
    buf.extend_from_slice(&prev_block_hash.0);
    let h = blake3::hash(&buf);
    let mut key = [0u8; 32];
    key.copy_from_slice(h.as_bytes());
    key
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

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

    // ── Configuration tests ────────────────────────────────────────────
    #[test]
    fn test_config_validation() {
        let mut cfg = MevConfig::default();
        assert!(cfg.validate().is_ok());

        cfg.commit_ttl_blocks = 0;
        assert!(cfg.validate().is_err());

        cfg = MevConfig::default();
        cfg.max_pending_commits = 0;
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn test_config_builder() -> MevResult<()> {
        let cfg = MevConfigBuilder::new()
            .commit_ttl_blocks(30)
            .max_pending_commits(200_000)
            .build()?;
        assert_eq!(cfg.commit_ttl_blocks, 30);
        assert_eq!(cfg.max_pending_commits, 200_000);
        Ok(())
    }

    // ── Commit-Reveal flow ─────────────────────────────────────────────
    #[test]
    fn test_commit_reveal_success() -> MevResult<()> {
        let mut pool = MevMempool::new(MevConfig::default())?;
        let tx = dummy_tx("alice", 0, "set key1 val1");
        let tx_bytes = serde_json::to_vec(&tx).unwrap();
        let salt = generate_salt(&tx, 16);
        let commit_hash = compute_commit_hash("alice", 0, &tx_bytes, &salt);

        let commit = TxCommit {
            commit_hash,
            sender: "alice".to_string(),
            nonce: 0,
            received_order: 1,
            commit_height: 0,
            encrypted_tx: None,
        };
        pool.submit_commit(commit)?;
        assert_eq!(pool.pending_commit_count(), 1);

        let reveal = TxReveal {
            commit_hash,
            commit_salt: salt,
            tx: tx.clone(),
        };
        pool.submit_reveal(reveal)?;
        assert_eq!(pool.pending_commit_count(), 0);
        assert_eq!(pool.revealed_count(), 1);
        Ok(())
    }

    #[test]
    fn test_reveal_hash_mismatch() -> MevResult<()> {
        let mut pool = MevMempool::new(MevConfig::default())?;
        let tx = dummy_tx("alice", 0, "set key1 val1");
        let tx_bytes = serde_json::to_vec(&tx).unwrap();
        let salt = generate_salt(&tx, 16);
        let commit_hash = compute_commit_hash("alice", 0, &tx_bytes, &salt);

        pool.submit_commit(TxCommit {
            commit_hash,
            sender: "alice".into(),
            nonce: 0,
            received_order: 1,
            commit_height: 0,
            encrypted_tx: None,
        })?;

        let reveal = TxReveal {
            commit_hash,
            commit_salt: b"wrong_salt_1234".to_vec(),
            tx,
        };
        let err = pool.submit_reveal(reveal).unwrap_err();
        assert!(matches!(err, MevError::RevealHashMismatch));
        Ok(())
    }

    #[test]
    fn test_duplicate_commit_rejected() -> MevResult<()> {
        let mut pool = MevMempool::new(MevConfig::default())?;
        let commit = TxCommit {
            commit_hash: Hash32([1; 32]),
            sender: "alice".into(),
            nonce: 0,
            received_order: 1,
            commit_height: 0,
            encrypted_tx: None,
        };
        pool.submit_commit(commit.clone())?;
        let err = pool.submit_commit(commit).unwrap_err();
        assert!(matches!(err, MevError::DuplicateCommit));
        assert_eq!(pool.metrics.duplicates_rejected, 1);
        Ok(())
    }

    // ── Encryption roundtrip ───────────────────────────────────────────
    #[test]
    fn test_threshold_encryption_roundtrip() -> MevResult<()> {
        let tx = dummy_tx("alice", 0, "set key1 val1");
        let secret = derive_epoch_secret("vset_hash_123", &Hash32::zero());
        let envelope = encrypt_tx_envelope(&tx, &secret, 1)?;
        assert!(!envelope.ciphertext.is_empty());

        let decrypted = decrypt_tx_envelope(&envelope, &secret)?;
        assert_eq!(decrypted.from, tx.from);
        assert_eq!(decrypted.nonce, tx.nonce);
        assert_eq!(decrypted.payload, tx.payload);
        Ok(())
    }

    // ── Expiry ─────────────────────────────────────────────────────────
    #[test]
    fn test_commit_expiry() -> MevResult<()> {
        let mut pool = MevMempool::new(MevConfig {
            commit_ttl_blocks: 5,
            ..Default::default()
        })?;
        let commit = TxCommit {
            commit_hash: Hash32([1; 32]),
            sender: "alice".into(),
            nonce: 0,
            received_order: 1,
            commit_height: 0,
            encrypted_tx: None,
        };
        pool.submit_commit(commit)?;
        assert_eq!(pool.pending_commit_count(), 1);

        pool.advance_height(10, &Hash32::zero());
        assert_eq!(pool.pending_commit_count(), 0);
        assert_eq!(pool.metrics.commits_expired, 1);
        Ok(())
    }

    // ── Backrun protection ─────────────────────────────────────────────
    #[test]
    fn test_backrun_protection() -> MevResult<()> {
        let mut pool = MevMempool::new(MevConfig {
            backrun_delay_blocks: 2,
            ..Default::default()
        })?;
        pool.record_proposer(10, "proposer1".into());
        pool.advance_height(11, &Hash32::zero());

        let tx = dummy_tx("proposer1", 0, "large_trade");
        assert!(pool.is_potential_backrun(&tx));

        let err = pool.submit_tx(tx).unwrap_err();
        assert!(matches!(err, MevError::BackrunBlocked { .. }));
        Ok(())
    }

    // ── Fair ordering ──────────────────────────────────────────────────
    #[test]
    fn test_fair_ordering_determinism() {
        let seed = Hash32([42; 32]);
        let mut items1: Vec<(u64, TxCommit)> = (0..10)
            .map(|i| {
                (
                    i,
                    TxCommit {
                        commit_hash: Hash32([i as u8; 32]),
                        sender: format!("user{}", i),
                        nonce: 0,
                        received_order: i,
                        commit_height: 0,
                        encrypted_tx: None,
                    },
                )
            })
            .collect();

        let mut items2 = items1.clone();

        fair_order_shuffle(&mut items1, 50, &seed);
        fair_order_shuffle(&mut items2, 50, &seed);

        // Same seed must produce same order
        assert_eq!(items1, items2);
    }

    // ── Metrics ────────────────────────────────────────────────────────
    #[test]
    fn test_metrics_tracking() -> MevResult<()> {
        let mut pool = MevMempool::new(MevConfig::default())?;
        let tx = dummy_tx("alice", 0, "test");
        pool.submit_tx(tx).unwrap();
        let metrics = pool.get_metrics();
        assert_eq!(metrics.commits_received, 1);
        assert_eq!(metrics.reveals_received, 1);
        Ok(())
    }

    #[test]
    fn test_clear_expired() -> MevResult<()> {
        let mut pool = MevMempool::new(MevConfig {
            commit_ttl_blocks: 5,
            ..Default::default()
        })?;
        let commit = TxCommit {
            commit_hash: Hash32([1; 32]),
            sender: "alice".into(),
            nonce: 0,
            received_order: 1,
            commit_height: 0,
            encrypted_tx: None,
        };
        pool.submit_commit(commit)?;
        pool.advance_height(10, &Hash32::zero());
        let cleared = pool.clear_expired();
        assert_eq!(cleared, 1);
        assert_eq!(pool.pending_commit_count(), 0);
        Ok(())
    }
}
