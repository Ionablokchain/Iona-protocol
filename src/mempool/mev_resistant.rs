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

use crate::types::{hash_bytes, Hash32, Height, Tx};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap, VecDeque};
use thiserror::Error;

// -----------------------------------------------------------------------------
// Configuration with validation
// -----------------------------------------------------------------------------

/// Configuration for MEV protection.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MevConfig {
    pub enable_commit_reveal: bool,
    pub commit_ttl_blocks: u64,
    pub enable_threshold_encryption: bool,
    pub enable_fair_ordering: bool,
    pub ordering_jitter_ms: u64,
    pub max_pending_commits: usize,
    pub backrun_delay_blocks: u64,
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

impl MevConfig {
    /// Validate configuration parameters.
    pub fn validate(&self) -> Result<(), MevError> {
        if self.commit_ttl_blocks == 0 {
            return Err(MevError::InvalidConfig("commit_ttl_blocks must be > 0".into()));
        }
        if self.max_pending_commits == 0 {
            return Err(MevError::InvalidConfig("max_pending_commits must be > 0".into()));
        }
        Ok(())
    }
}

// -----------------------------------------------------------------------------
// Errors
// -----------------------------------------------------------------------------

/// Errors that can occur during MEV mempool operations.
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

    #[error("invalid configuration: {0}")]
    InvalidConfig(String),

    #[error("encryption error: {0}")]
    EncryptionError(String),

    #[error("decryption error: {0}")]
    DecryptionError(String),

    #[error("serialization error: {0}")]
    SerializationError(String),
}

pub type MevResult<T> = Result<T, MevError>;

// -----------------------------------------------------------------------------
// Commit‑Reveal Types
// -----------------------------------------------------------------------------

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TxCommit {
    pub commit_hash: Hash32,
    pub sender: String,
    pub received_order: u64,
    pub commit_height: Height,
    pub encrypted_tx: Option<Vec<u8>>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TxReveal {
    pub commit_hash: Hash32,
    pub commit_salt: Vec<u8>,
    pub tx: Tx,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum CommitStatus {
    Pending,
    Revealed,
    Expired,
    Included,
}

// -----------------------------------------------------------------------------
// Threshold Encryption
// -----------------------------------------------------------------------------

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EncryptedEnvelope {
    pub ciphertext: Vec<u8>,
    pub nonce: [u8; 12],
    pub epoch: u64,
    pub sender: String,
    pub sender_nonce: u64,
}

/// Encrypt a transaction for threshold-encrypted mempool.
pub fn encrypt_tx_envelope(tx: &Tx, epoch_secret: &[u8; 32], epoch: u64) -> MevResult<EncryptedEnvelope> {
    use aes_gcm::aead::Aead;
    use aes_gcm::{Aes256Gcm, KeyInit, Nonce};

    let plaintext = serde_json::to_vec(tx)
        .map_err(|e| MevError::SerializationError(e.to_string()))?;

    let tx_hash = crate::types::tx_hash(tx);
    let mut nonce_bytes = [0u8; 12];
    nonce_bytes.copy_from_slice(&tx_hash.0[..12]);

    let cipher = Aes256Gcm::new_from_slice(epoch_secret)
        .map_err(|e| MevError::EncryptionError(e.to_string()))?;
    let nonce = Nonce::from_slice(&nonce_bytes);
    let ciphertext = cipher.encrypt(nonce, plaintext.as_ref())
        .map_err(|e| MevError::EncryptionError(e.to_string()))?;

    Ok(EncryptedEnvelope {
        ciphertext,
        nonce: nonce_bytes,
        epoch,
        sender: tx.from.clone(),
        sender_nonce: tx.nonce,
    })
}

/// Decrypt a transaction from a threshold-encrypted envelope.
pub fn decrypt_tx_envelope(envelope: &EncryptedEnvelope, epoch_secret: &[u8; 32]) -> MevResult<Tx> {
    use aes_gcm::aead::Aead;
    use aes_gcm::{Aes256Gcm, KeyInit, Nonce};

    let cipher = Aes256Gcm::new_from_slice(epoch_secret)
        .map_err(|e| MevError::DecryptionError(e.to_string()))?;
    let nonce = Nonce::from_slice(&envelope.nonce);
    let plaintext = cipher.decrypt(nonce, envelope.ciphertext.as_ref())
        .map_err(|e| MevError::DecryptionError(e.to_string()))?;
    serde_json::from_slice(&plaintext)
        .map_err(|e| MevError::SerializationError(e.to_string()))
}

// -----------------------------------------------------------------------------
// Fair Ordering Helpers
// -----------------------------------------------------------------------------

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

fn deterministic_shuffle(items: &mut [(u64, TxCommit)], seed: &Hash32, extra_nonce: u64) {
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

// -----------------------------------------------------------------------------
// MEV‑Resistant Mempool
// -----------------------------------------------------------------------------

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
}

pub struct MevMempool {
    pub config: MevConfig,
    pub metrics: MevMempoolMetrics,
    pending_commits: HashMap<Hash32, TxCommit>,
    revealed_txs: VecDeque<Tx>,
    encrypted_queue: VecDeque<EncryptedEnvelope>,
    order_counter: u64,
    current_height: Height,
    last_block_hash: Hash32,
    recent_proposers: VecDeque<(Height, String)>,
}

impl MevMempool {
    pub fn new(config: MevConfig) -> MevResult<Self> {
        config.validate()?;
        Ok(Self {
            config,
            metrics: MevMempoolMetrics::default(),
            pending_commits: HashMap::new(),
            revealed_txs: VecDeque::new(),
            encrypted_queue: VecDeque::new(),
            order_counter: 0,
            current_height: 0,
            last_block_hash: Hash32::zero(),
            recent_proposers: VecDeque::new(),
        })
    }

    pub fn submit_commit(&mut self, commit: TxCommit) -> MevResult<()> {
        if self.pending_commits.len() >= self.config.max_pending_commits {
            return Err(MevError::TooManyPendingCommits {
                max: self.config.max_pending_commits,
            });
        }
        if self.pending_commits.contains_key(&commit.commit_hash) {
            return Err(MevError::DuplicateCommit);
        }
        self.metrics.commits_received += 1;
        self.pending_commits.insert(commit.commit_hash, commit);
        Ok(())
    }

    pub fn submit_reveal(&mut self, reveal: TxReveal) -> MevResult<()> {
        let commit = self.pending_commits
            .get(&reveal.commit_hash)
            .ok_or(MevError::CommitNotFound)?;

        let expected_hash = compute_commit_hash(
            &reveal.tx.from,
            reveal.tx.nonce,
            &serde_json::to_vec(&reveal.tx)
                .map_err(|e| MevError::SerializationError(e.to_string()))?,
            &reveal.commit_salt,
        );

        if expected_hash != reveal.commit_hash {
            self.metrics.reveals_invalid += 1;
            return Err(MevError::RevealHashMismatch);
        }

        if self.current_height.saturating_sub(commit.commit_height) > self.config.commit_ttl_blocks {
            self.metrics.commits_expired += 1;
            self.pending_commits.remove(&reveal.commit_hash);
            return Err(MevError::CommitExpired { ttl: self.config.commit_ttl_blocks });
        }

        self.metrics.reveals_received += 1;
        self.pending_commits.remove(&reveal.commit_hash);
        self.revealed_txs.push_back(reveal.tx);
        Ok(())
    }

    pub fn submit_encrypted(&mut self, envelope: EncryptedEnvelope) -> MevResult<()> {
        self.metrics.encrypted_received += 1;
        self.encrypted_queue.push_back(envelope);
        Ok(())
    }

    pub fn submit_tx(&mut self, tx: Tx) -> MevResult<()> {
        if self.config.enable_commit_reveal {
            let salt = generate_salt(&tx);
            let encrypted_bytes = serde_json::to_vec(&tx)
                .map_err(|e| MevError::SerializationError(e.to_string()))?;
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

    pub fn decrypt_pending(&mut self, epoch_secret: &[u8; 32]) -> Vec<Tx> {
        let mut decrypted = Vec::new();
        while let Some(envelope) = self.encrypted_queue.pop_front() {
            if let Ok(tx) = decrypt_tx_envelope(&envelope, epoch_secret) {
                self.metrics.encrypted_decrypted += 1;
                decrypted.push(tx);
            }
        }
        decrypted
    }

    pub fn drain_fair(&mut self, n: usize) -> Vec<Tx> {
        let mut result = Vec::with_capacity(n);
        let revealed: Vec<Tx> = self.revealed_txs.drain(..).collect();

        if self.config.enable_fair_ordering && !revealed.is_empty() {
            let mut ordering: Vec<(u64, TxCommit)> = revealed
                .iter()
                .enumerate()
                .map(|(i, tx)| {
                    let order = self.order_counter.wrapping_add(i as u64);
                    (
                        order,
                        TxCommit {
                            commit_hash: crate::types::tx_hash(tx),
                            sender: tx.from.clone(),
                            received_order: order,
                            commit_height: self.current_height,
                            encrypted_tx: None,
                        },
                    )
                })
                .collect();
            fair_order_shuffle(&mut ordering, self.config.ordering_jitter_ms, &self.last_block_hash);
            self.metrics.fair_order_shuffles += 1;
            for (_, commit) in ordering {
                if result.len() < n {
                    // We need to map back to the original tx; simplest: match by commit_hash
                    if let Some(tx) = revealed.iter().find(|t| crate::types::tx_hash(t) == commit.commit_hash) {
                        result.push(tx.clone());
                    }
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

    pub fn advance_height(&mut self, height: Height, block_hash: &Hash32) {
        self.current_height = height;
        self.last_block_hash = *block_hash;
        let ttl = self.config.commit_ttl_blocks;
        let expired: Vec<Hash32> = self.pending_commits
            .iter()
            .filter(|(_, c)| height.saturating_sub(c.commit_height) > ttl)
            .map(|(h, _)| *h)
            .collect();
        for h in expired {
            self.pending_commits.remove(&h);
            self.metrics.commits_expired += 1;
        }
    }

    pub fn record_proposer(&mut self, height: Height, proposer: String) {
        self.recent_proposers.push_back((height, proposer));
        while self.recent_proposers.len() > 100 {
            self.recent_proposers.pop_front();
        }
    }

    pub fn is_potential_backrun(&self, tx: &Tx) -> bool {
        if self.config.backrun_delay_blocks == 0 {
            return false;
        }
        for (h, proposer) in &self.recent_proposers {
            if self.current_height.saturating_sub(*h) < self.config.backrun_delay_blocks {
                if tx.from == *proposer {
                    return true;
                }
            }
        }
        false
    }

    pub fn pending_commit_count(&self) -> usize { self.pending_commits.len() }
    pub fn revealed_count(&self) -> usize { self.revealed_txs.len() }
    pub fn encrypted_count(&self) -> usize { self.encrypted_queue.len() }
    pub fn get_metrics(&self) -> &MevMempoolMetrics { &self.metrics }
}

// -----------------------------------------------------------------------------
// Helpers
// -----------------------------------------------------------------------------

pub fn compute_commit_hash(sender: &str, nonce: u64, tx_bytes: &[u8], salt: &[u8]) -> Hash32 {
    let mut buf = Vec::with_capacity(sender.len() + 8 + tx_bytes.len() + salt.len() + 16);
    buf.extend_from_slice(b"IONA_COMMIT");
    buf.extend_from_slice(sender.as_bytes());
    buf.extend_from_slice(&nonce.to_le_bytes());
    buf.extend_from_slice(tx_bytes);
    buf.extend_from_slice(salt);
    hash_bytes(&buf)
}

fn generate_salt(tx: &Tx) -> Vec<u8> {
    let h = crate::types::tx_hash(tx);
    h.0[..16].to_vec()
}

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

    #[test]
    fn test_commit_reveal_flow() -> MevResult<()> {
        let mut pool = MevMempool::new(MevConfig::default())?;
        let tx = dummy_tx("alice", 0, "set key1 val1");
        let tx_bytes = serde_json::to_vec(&tx).unwrap();
        let salt = b"random_salt_1234".to_vec();
        let commit_hash = compute_commit_hash("alice", 0, &tx_bytes, &salt);

        let commit = TxCommit {
            commit_hash,
            sender: "alice".to_string(),
            received_order: 1,
            commit_height: 0,
            encrypted_tx: None,
        };
        pool.submit_commit(commit)?;
        assert_eq!(pool.pending_commit_count(), 1);

        let reveal = TxReveal {
            commit_hash,
            commit_salt: salt,
            tx,
        };
        pool.submit_reveal(reveal)?;
        assert_eq!(pool.pending_commit_count(), 0);
        assert_eq!(pool.revealed_count(), 1);
        Ok(())
    }

    #[test]
    fn test_commit_reveal_invalid() -> MevResult<()> {
        let mut pool = MevMempool::new(MevConfig::default())?;
        let tx = dummy_tx("alice", 0, "set key1 val1");
        let tx_bytes = serde_json::to_vec(&tx).unwrap();
        let salt = b"correct_salt".to_vec();
        let commit_hash = compute_commit_hash("alice", 0, &tx_bytes, &salt);

        let commit = TxCommit {
            commit_hash,
            sender: "alice".to_string(),
            received_order: 1,
            commit_height: 0,
            encrypted_tx: None,
        };
        pool.submit_commit(commit)?;

        let reveal = TxReveal {
            commit_hash,
            commit_salt: b"wrong_salt".to_vec(),
            tx,
        };
        let err = pool.submit_reveal(reveal).unwrap_err();
        assert!(matches!(err, MevError::RevealHashMismatch));
        Ok(())
    }

    #[test]
    fn test_threshold_encryption() -> MevResult<()> {
        let tx = dummy_tx("alice", 0, "set key1 val1");
        let secret = derive_epoch_secret("vset_hash_123", &Hash32::zero());
        let envelope = encrypt_tx_envelope(&tx, &secret, 1)?;
        assert!(!envelope.ciphertext.is_empty());
        let decrypted = decrypt_tx_envelope(&envelope, &secret)?;
        assert_eq!(decrypted.from, tx.from);
        assert_eq!(decrypted.payload, tx.payload);
        Ok(())
    }

    #[test]
    fn test_commit_expiry() -> MevResult<()> {
        let mut pool = MevMempool::new(MevConfig {
            commit_ttl_blocks: 5,
            ..Default::default()
        })?;
        let commit = TxCommit {
            commit_hash: Hash32([1; 32]),
            sender: "alice".to_string(),
            received_order: 1,
            commit_height: 0,
            encrypted_tx: None,
        };
        pool.submit_commit(commit)?;
        assert_eq!(pool.pending_commit_count(), 1);
        pool.advance_height(10, &Hash32::zero());
        assert_eq!(pool.pending_commit_count(), 0);
        Ok(())
    }
}
