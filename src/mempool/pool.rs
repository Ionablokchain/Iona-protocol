/// Production mempool for IONA.
///
/// Features vs v18 reference:
/// - Per-sender nonce-ordered queues (ensures tx sequence integrity)
/// - Replace-by-fee (RBF): re-submitting same nonce with >=10% higher tip replaces the old tx
/// - TTL: transactions expire after TTL_BLOCKS blocks
/// - Admission: rejects tx if sender's pending count exceeds MAX_PENDING_PER_SENDER
/// - Eviction: when pool is full, drops lowest-priority tx from other senders
/// - Metrics: exposes counters for admitted/rejected/evicted/expired

use crate::execution::intrinsic_gas;
use crate::types::{Height, Tx};
use std::collections::{BTreeMap, BinaryHeap, HashMap};
use std::cmp::Ordering;

const TTL_BLOCKS: u64 = 300;
const MAX_PENDING_PER_SENDER: usize = 64;
const RBF_BUMP_PERCENT: u64 = 10;

#[derive(Clone, Debug)]
struct PendingTx {
    tx: Tx,
    score: u128,
    inserted_height: Height,
}

impl PendingTx {
    fn new(tx: Tx, current_height: Height) -> Self {
        let gas = intrinsic_gas(&tx) as u128;
        let tip = (tx.max_priority_fee_per_gas as u128).saturating_mul(gas);
        let size = (tx.payload.len() as u128 + 128).max(1);
        let score = tip.saturating_mul(1_000_000) / size;
        Self { tx, score, inserted_height: current_height }
    }

    fn is_expired(&self, current_height: Height) -> bool {
        current_height.saturating_sub(self.inserted_height) > TTL_BLOCKS
    }
}

#[derive(Clone)]
struct HeapEntry { score: u128, nonce: u64, sender: String }
impl PartialEq for HeapEntry { fn eq(&self, o: &Self) -> bool { self.score == o.score } }
impl Eq for HeapEntry {}
impl PartialOrd for HeapEntry { fn partial_cmp(&self, o: &Self) -> Option<Ordering> { Some(self.cmp(o)) } }
impl Ord for HeapEntry {
    fn cmp(&self, o: &Self) -> Ordering {
        self.score.cmp(&o.score).then_with(|| o.nonce.cmp(&self.nonce))
    }
}

#[derive(Default, Debug, Clone)]
pub struct MempoolMetrics {
    pub admitted: u64,
    pub rejected_dup: u64,
    pub rejected_full: u64,
    pub rejected_sender_limit: u64,
    pub evicted: u64,
    pub expired: u64,
    pub rbf_replaced: u64,
}

pub struct Mempool {
    cap: usize,
    current_height: Height,
    queues: HashMap<String, BTreeMap<u64, PendingTx>>,
    pub metrics: MempoolMetrics,
}

impl Default for Mempool {
    fn default() -> Self { Self::new(200_000) }
}

impl Mempool {
    pub fn new(cap: usize) -> Self {
        Self { cap, current_height: 0, queues: HashMap::new(), metrics: MempoolMetrics::default() }
    }

    pub fn len(&self) -> usize {
        self.queues.values().map(|q| q.len()).sum()
    }

    pub fn sender_count(&self) -> usize { self.queues.len() }

    /// Call after each committed block to expire old txs and clear confirmed nonces.
    pub fn advance_height(&mut self, height: Height) {
        self.current_height = height;
        let h = self.current_height;
        let metrics = &mut self.metrics;
        self.queues.retain(|_, queue| {
            let before = queue.len();
            queue.retain(|_, ptx| !ptx.is_expired(h));
            metrics.expired += (before - queue.len()) as u64;
            !queue.is_empty()
        });
    }

    /// Remove confirmed transactions (nonces below committed_nonce).
    pub fn remove_confirmed(&mut self, sender: &str, committed_nonce: u64) {
        if let Some(queue) = self.queues.get_mut(sender) {
            queue.retain(|&nonce, _| nonce >= committed_nonce);
            if queue.is_empty() { self.queues.remove(sender); }
        }
    }

    /// Submit a transaction. Returns Err with reason on rejection.
    /// `current_base_fee`: the current EIP-1559 base fee. Txs with max_fee < base_fee are rejected.
    pub fn push_with_base_fee(&mut self, tx: Tx, current_base_fee: u64) -> Result<bool, &'static str> {
        // EIP-1559: reject transactions that cannot pay the current base fee
        if tx.max_fee_per_gas < current_base_fee {
            self.metrics.rejected_dup += 1;
            return Err("max_fee_per_gas below current base fee");
        }
        self.push(tx)
    }

    /// Submit a transaction. Returns Err with reason on rejection.
    pub fn push(&mut self, tx: Tx) -> Result<bool, &'static str> {
        let sender = tx.from.clone();
        if sender.is_empty() { return Err("missing from address"); }

        let queue = self.queues.entry(sender.clone()).or_default();

        // RBF check
        if let Some(existing) = queue.get(&tx.nonce) {
            let existing_tip = existing.tx.max_priority_fee_per_gas;
            let required = existing_tip.saturating_add(
                (existing_tip.saturating_mul(RBF_BUMP_PERCENT) / 100).max(1)
            );
            if tx.max_priority_fee_per_gas < required {
                self.metrics.rejected_dup += 1;
                return Err("rbf: tip too low (need >=10% bump)");
            }
            queue.insert(tx.nonce, PendingTx::new(tx, self.current_height));
            self.metrics.rbf_replaced += 1;
            return Ok(false);
        }

        // Per-sender cap
        if queue.len() >= MAX_PENDING_PER_SENDER {
            self.metrics.rejected_sender_limit += 1;
            return Err("sender queue full");
        }

        // Global cap with eviction
        if self.len() >= self.cap {
            if !self.evict_worst(&sender) {
                self.metrics.rejected_full += 1;
                return Err("mempool full");
            }
        }

        let ptx = PendingTx::new(tx, self.current_height);
        self.queues.entry(sender).or_default().insert(ptx.tx.nonce, ptx);
        self.metrics.admitted += 1;
        Ok(true)
    }

    fn evict_worst(&mut self, protect_sender: &str) -> bool {
        let worst = self.queues.iter()
            .filter(|(s, _)| s.as_str() != protect_sender)
            .flat_map(|(s, q)| q.iter().map(move |(n, p)| (p.score, s.clone(), *n)))
            .min_by_key(|(score, _, _)| *score);
        if let Some((_, sender, nonce)) = worst {
            if let Some(q) = self.queues.get_mut(&sender) {
                q.remove(&nonce);
                if q.is_empty() { self.queues.remove(&sender); }
            }
            self.metrics.evicted += 1;
            true
        } else {
            false
        }
    }

    /// Drain up to `n` transactions in priority order, respecting per-sender nonce ordering.
    pub fn drain_best(&mut self, n: usize) -> Vec<Tx> {
        let mut heap: BinaryHeap<HeapEntry> = self.queues.iter()
            .filter_map(|(sender, queue)| {
                queue.values().next().map(|ptx| HeapEntry {
                    score: ptx.score,
                    nonce: ptx.tx.nonce,
                    sender: sender.clone(),
                })
            })
            .collect();

        let mut result = Vec::with_capacity(n);
        while result.len() < n {
            let entry = match heap.pop() { Some(e) => e, None => break };
            let queue = match self.queues.get_mut(&entry.sender) { Some(q) => q, None => continue };
            let ptx = match queue.remove(&entry.nonce) { Some(p) => p, None => continue };
            result.push(ptx.tx);
            if let Some(next) = queue.values().next() {
                heap.push(HeapEntry { score: next.score, nonce: next.tx.nonce, sender: entry.sender.clone() });
            } else {
                self.queues.remove(&entry.sender);
            }
        }
        result
    }
}
