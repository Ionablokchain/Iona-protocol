use serde::{Serialize, Deserialize};
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};

/// Mempool entry – raw signed transaction bytes plus metadata needed for ordering and replacement.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PendingTx {
    pub hash: String,
    pub from: String,      // 0x-prefixed address
    pub nonce: u64,
    pub tx_type: u8,       // 0 = legacy, 1 = EIP-2930, 2 = EIP-1559
    pub gas_limit: u64,
    pub gas_price: u128,                    // for legacy/2930
    pub max_fee_per_gas: Option<u128>,      // for EIP-1559
    pub max_priority_fee_per_gas: Option<u128>, // for EIP-1559
    pub raw: Vec<u8>,
    pub inserted_at: u64, // unix timestamp (seconds)
}

impl PendingTx {
    /// Effective tip used for ordering (max_priority_fee for 1559, otherwise gas_price).
    pub fn priority(&self) -> u128 {
        self.max_priority_fee_per_gas.unwrap_or(self.gas_price)
    }

    /// Fee cap used for replacement (max_fee for 1559, otherwise gas_price).
    pub fn fee_cap(&self) -> u128 {
        self.max_fee_per_gas.unwrap_or(self.gas_price)
    }
}

/// Key for global ordering by insertion time (used for pruning).
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
struct TxAgeKey {
    inserted_at: u64,
    sender: String,
    nonce: u64,
}

/// Mempool with per-sender nonce lanes, strict replacement rules,
/// hash index, and efficient pruning.
#[derive(Default, Clone, Serialize, Deserialize)]
pub struct TxPool {
    /// Primary storage: sender -> nonce -> transaction.
    by_sender: HashMap<String, BTreeMap<u64, PendingTx>>,
    /// Secondary index: hash -> (sender, nonce, inserted_at) for O(1) removal.
    by_hash: HashMap<String, (String, u64, u64)>,
    /// Global ordering by insertion time (for pruning).
    age_order: BTreeSet<TxAgeKey>,
}

// Helper functions for comparing old vs new fee caps and priorities.
impl TxPool {
    /// Extracts the old fee cap from an existing transaction (works across types).
    fn old_fee_cap(old_gas_price: u128, old_max_fee: Option<u128>) -> u128 {
        old_max_fee.unwrap_or(old_gas_price)
    }

    /// Extracts the old priority from an existing transaction (works across types).
    fn old_priority(old_gas_price: u128, old_max_priority: Option<u128>) -> u128 {
        old_max_priority.unwrap_or(old_gas_price)
    }
}

impl TxPool {
    /// Total number of pending transactions.
    pub fn len(&self) -> usize {
        self.by_hash.len()
    }

    /// Number of pending transactions for a specific sender.
    pub fn pending_for_sender(&self, sender: &str) -> usize {
        self.by_sender.get(sender).map(|m| m.len()).unwrap_or(0)
    }

    /// Insert a new transaction. Implements strict replacement rules:
    /// - If the new transaction has the same type as the old one, we enforce:
    ///   * For EIP-1559: strictly higher max_fee_per_gas AND max_priority_fee_per_gas.
    ///   * For legacy/EIP-2930: strictly higher gas_price.
    /// - If types differ, we compare by fee_cap() and priority() (both must be strictly higher)
    ///   to avoid underpriced replacements across types.
    pub fn insert(&mut self, tx: PendingTx) -> Result<(), String> {
        // Check if we already have a transaction with the same hash.
        if self.by_hash.contains_key(&tx.hash) {
            return Err("transaction already in pool".into());
        }

        let sender = tx.from.clone();
        let nonce = tx.nonce;
        let inserted_at = tx.inserted_at;

        // First, check for an existing transaction at the same sender/nonce.
        // We need to extract its metadata without holding a borrow on `by_sender`.
        let old_meta = self.by_sender.get(&sender).and_then(|lane| {
            lane.get(&nonce).map(|existing| {
                (
                    existing.hash.clone(),
                    existing.inserted_at,
                    existing.tx_type,
                    existing.gas_price,
                    existing.max_fee_per_gas,
                    existing.max_priority_fee_per_gas,
                )
            })
        });

        // If there is an existing transaction, apply replacement rules.
        if let Some((old_hash, old_inserted_at, old_type, old_gas_price, old_max_fee, old_max_priority)) = old_meta {
            // Determine if the new transaction can replace the old one.
            let can_replace = match (tx.tx_type, old_type) {
                (2, 2) => {
                    // Both are EIP-1559: must increase both max_fee and max_priority_fee.
                    let new_max_fee = tx.max_fee_per_gas.unwrap_or(0);
                    let new_max_priority = tx.max_priority_fee_per_gas.unwrap_or(0);
                    new_max_fee > old_max_fee.unwrap_or(0) && new_max_priority > old_max_priority.unwrap_or(0)
                }
                (1, 1) | (0, 0) => {
                    // Same legacy or EIP-2930: must increase gas_price.
                    tx.gas_price > old_gas_price
                }
                _ => {
                    // Mixed types: require strictly higher fee_cap AND priority.
                    tx.fee_cap() > Self::old_fee_cap(old_gas_price, old_max_fee)
                        && tx.priority() > Self::old_priority(old_gas_price, old_max_priority)
                }
            };

            if !can_replace {
                return Err("replacement underpriced".into());
            }

            // Remove the old transaction from indexes.
            self.by_hash.remove(&old_hash);
            let age_key = TxAgeKey {
                inserted_at: old_inserted_at,
                sender: sender.clone(),
                nonce,
            };
            self.age_order.remove(&age_key);
        }

        // Now insert the new transaction.
        // Re-borrow lane (the old one is gone if it existed).
        let lane = self.by_sender.entry(sender.clone()).or_insert_with(BTreeMap::new);
        lane.insert(nonce, tx.clone());

        // Update indexes.
        self.by_hash.insert(tx.hash.clone(), (sender.clone(), nonce, inserted_at));
        let age_key = TxAgeKey {
            inserted_at,
            sender,
            nonce,
        };
        self.age_order.insert(age_key);

        Ok(())
    }

    /// Get the next batch of ready transactions (by nonce) without removing them.
    /// For each sender, takes all transactions with consecutive nonces starting from the expected nonce.
    /// Returns up to `max` transactions, globally sorted by priority (descending).
    ///
    /// # Note
    /// The returned list is sorted by priority, not by sender/nonce order.
    /// When building a block, the caller **must** re-order the transactions
    /// to preserve per-sender nonce ordering before execution.
    pub fn ready_txs(&self, account_nonces: &HashMap<String, u64>, max: usize) -> Vec<PendingTx> {
        let mut candidates = Vec::new();

        for (sender, lane) in &self.by_sender {
            let expected = account_nonces.get(sender).copied().unwrap_or(0);
            let mut nonce = expected;
            while let Some(tx) = lane.get(&nonce) {
                candidates.push(tx.clone());
                nonce += 1;
            }
        }

        // Sort by priority descending (highest tip first).
        candidates.sort_by(|a, b| b.priority().cmp(&a.priority()));
        candidates.truncate(max);
        candidates
    }

    /// Remove confirmed transactions by hash (e.g., after they are included in a block).
    /// Returns the number of removed transactions.
    pub fn remove_confirmed(&mut self, hashes: &HashSet<String>) -> usize {
        let mut removed = 0;
        for hash in hashes {
            if let Some((sender, nonce, inserted_at)) = self.by_hash.remove(hash) {
                // Remove from primary storage.
                let mut remove_sender = false;
                if let Some(lane) = self.by_sender.get_mut(&sender) {
                    lane.remove(&nonce);
                    remove_sender = lane.is_empty();
                }
                if remove_sender {
                    self.by_sender.remove(&sender);
                }

                // Remove from age order.
                let age_key = TxAgeKey {
                    inserted_at,
                    sender,
                    nonce,
                };
                self.age_order.remove(&age_key);
                removed += 1;
            }
        }
        removed
    }

    /// Prune old transactions and enforce size limit.
    /// - Removes any transaction older than `max_age_secs`.
    /// - If total size exceeds `max_total`, keeps the newest `max_total` by insertion time.
    pub fn prune(&mut self, now_secs: u64, max_age_secs: u64, max_total: usize) {
        // 1. Remove by age.
        let cutoff = now_secs.saturating_sub(max_age_secs);
        let old_keys: Vec<TxAgeKey> = self.age_order
            .iter()
            .take_while(|key| key.inserted_at < cutoff)
            .cloned()
            .collect();

        for key in old_keys {
            // Remove from primary storage.
            let mut remove_sender = false;
            if let Some(lane) = self.by_sender.get_mut(&key.sender) {
                if let Some(tx) = lane.remove(&key.nonce) {
                    self.by_hash.remove(&tx.hash);
                }
                remove_sender = lane.is_empty();
            }
            if remove_sender {
                self.by_sender.remove(&key.sender);
            }

            // Remove from age order.
            self.age_order.remove(&key);
        }

        // 2. Enforce size limit (keep newest).
        if self.len() > max_total {
            // Collect all age keys, sort ascending (oldest first).
            let mut all_keys: Vec<TxAgeKey> = self.age_order.iter().cloned().collect();
            all_keys.sort(); // ascending by inserted_at.
            let to_remove = all_keys.len() - max_total;
            for key in all_keys.into_iter().take(to_remove) {
                let mut remove_sender = false;
                if let Some(lane) = self.by_sender.get_mut(&key.sender) {
                    if let Some(tx) = lane.remove(&key.nonce) {
                        self.by_hash.remove(&tx.hash);
                    }
                    remove_sender = lane.is_empty();
                }
                if remove_sender {
                    self.by_sender.remove(&key.sender);
                }
                self.age_order.remove(&key);
            }
        }
    }

    /// Check if a transaction exists by hash.
    pub fn contains(&self, hash: &str) -> bool {
        self.by_hash.contains_key(hash)
    }

    /// Get transaction by hash (if present).
    pub fn get_by_hash(&self, hash: &str) -> Option<&PendingTx> {
        self.by_hash.get(hash).and_then(|(sender, nonce, _)| {
            self.by_sender.get(sender)?.get(nonce)
        })
    }

    /// Get all transactions for a sender, in nonce order.
    pub fn txs_for_sender(&self, sender: &str) -> Vec<&PendingTx> {
        self.by_sender
            .get(sender)
            .map(|lane| lane.values().collect())
            .unwrap_or_default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dummy_tx(hash: &str, from: &str, nonce: u64, gas_price: u128, inserted_at: u64) -> PendingTx {
        PendingTx {
            hash: hash.to_string(),
            from: from.to_string(),
            nonce,
            tx_type: 0,
            gas_limit: 21000,
            gas_price,
            max_fee_per_gas: None,
            max_priority_fee_per_gas: None,
            raw: vec![],
            inserted_at,
        }
    }

    fn dummy_tx_1559(hash: &str, from: &str, nonce: u64, max_fee: u128, max_priority: u128, inserted_at: u64) -> PendingTx {
        PendingTx {
            hash: hash.to_string(),
            from: from.to_string(),
            nonce,
            tx_type: 2,
            gas_limit: 21000,
            gas_price: 0,
            max_fee_per_gas: Some(max_fee),
            max_priority_fee_per_gas: Some(max_priority),
            raw: vec![],
            inserted_at,
        }
    }

    #[test]
    fn test_insert_and_duplicate() {
        let mut pool = TxPool::default();
        let tx = dummy_tx("hash1", "alice", 0, 10, 100);
        assert!(pool.insert(tx).is_ok());
        assert_eq!(pool.len(), 1);
        // Same hash again -> error.
        let tx2 = dummy_tx("hash1", "alice", 0, 20, 101);
        assert!(pool.insert(tx2).is_err());
    }

    #[test]
    fn test_replacement_legacy() {
        let mut pool = TxPool::default();
        let tx1 = dummy_tx("hash1", "alice", 0, 10, 100);
        pool.insert(tx1).unwrap();
        // Replace with higher gas_price -> ok.
        let tx2 = dummy_tx("hash2", "alice", 0, 20, 101);
        assert!(pool.insert(tx2).is_ok());
        // Now pool should have only tx2.
        assert_eq!(pool.len(), 1);
        assert!(pool.contains("hash2"));
        assert!(!pool.contains("hash1"));
    }

    #[test]
    fn test_replacement_1559() {
        let mut pool = TxPool::default();
        let tx1 = dummy_tx_1559("hash1", "alice", 0, 100, 10, 100);
        pool.insert(tx1).unwrap();
        // Increase only max_fee -> should fail.
        let tx2 = dummy_tx_1559("hash2", "alice", 0, 200, 10, 101);
        assert!(pool.insert(tx2).is_err());
        // Increase both -> ok.
        let tx3 = dummy_tx_1559("hash3", "alice", 0, 200, 20, 102);
        assert!(pool.insert(tx3).is_ok());
        assert_eq!(pool.len(), 1);
        assert!(pool.contains("hash3"));
    }

    #[test]
    fn test_ready_txs() {
        let mut pool = TxPool::default();
        pool.insert(dummy_tx("hash1", "alice", 0, 5, 100)).unwrap();
        pool.insert(dummy_tx("hash2", "alice", 1, 4, 101)).unwrap();
        pool.insert(dummy_tx("hash3", "bob",   0, 10, 102)).unwrap();

        let mut account_nonces = HashMap::new();
        account_nonces.insert("alice".to_string(), 0);
        account_nonces.insert("bob".to_string(), 0);

        let ready = pool.ready_txs(&account_nonces, 10);
        assert_eq!(ready.len(), 3); // alice nonce0, alice nonce1, bob nonce0
        // Verify priority order: bob (10) > alice (5) > alice (4)
        assert_eq!(ready[0].hash, "hash3");
        assert_eq!(ready[1].hash, "hash1");
        assert_eq!(ready[2].hash, "hash2");

        // Remove alice nonce0 and see nonce1 still there but not ready because nonce0 missing.
        pool.remove_confirmed(&HashSet::from(["hash1".to_string()]));
        let ready2 = pool.ready_txs(&account_nonces, 10);
        assert_eq!(ready2.len(), 1); // only bob
    }

    #[test]
    fn test_prune_age() {
        let mut pool = TxPool::default();
        pool.insert(dummy_tx("hash1", "alice", 0, 5, 100)).unwrap();
        pool.insert(dummy_tx("hash2", "bob",   0, 5, 200)).unwrap();
        pool.prune(150, 100, 10); // now=150, max_age=100 → keep inserted_at >=50. hash1 (100) is ok, hash2 (200) is ok.
        assert_eq!(pool.len(), 2);
        pool.prune(250, 100, 10); // now=250, cutoff=150 → hash1 (100) too old, should be removed.
        assert_eq!(pool.len(), 1);
        assert!(pool.contains("hash2"));
    }

    #[test]
    fn test_prune_size() {
        let mut pool = TxPool::default();
        pool.insert(dummy_tx("hash1", "alice", 0, 5, 100)).unwrap();
        pool.insert(dummy_tx("hash2", "bob",   0, 5, 200)).unwrap();
        pool.insert(dummy_tx("hash3", "carol", 0, 5, 150)).unwrap();
        pool.prune(1000, 10000, 2); // max_total=2 → keep newest 2.
        assert_eq!(pool.len(), 2);
        // Newest are hash2 (200) and hash3 (150). hash1 (100) should be gone.
        assert!(!pool.contains("hash1"));
        assert!(pool.contains("hash2"));
        assert!(pool.contains("hash3"));
    }

    #[test]
    fn test_remove_confirmed_consistency() {
        let mut pool = TxPool::default();
        pool.insert(dummy_tx("hash1", "alice", 0, 5, 100)).unwrap();
        pool.insert(dummy_tx("hash2", "bob",   0, 5, 200)).unwrap();
        pool.remove_confirmed(&HashSet::from(["hash1".to_string()]));

        // age_order should no longer contain hash1.
        assert_eq!(pool.age_order.len(), 1);
        assert_eq!(pool.len(), 1);
        assert!(pool.contains("hash2"));
        assert!(!pool.contains("hash1"));
    }
}
