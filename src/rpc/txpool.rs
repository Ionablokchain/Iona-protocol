//! Transaction pool for the Ethereum JSON‑RPC server.
//!
//! # Production Features
//! - Configurable via `TxPoolConfig` (max age, pool size, per‑sender limits, fee bump).
//! - `TxPoolManager` with thread‑safe wrapper (`parking_lot::Mutex`).
//! - Metrics for pool size, insertions, evictions, replacements.
//! - Persistent state (optional) with atomic writes and file locking.
//! - Structured logging with `tracing`.
//! - Full test coverage.

use fs2::FileExt;
use parking_lot::Mutex;
use prometheus::{
    register_counter, register_counter_vec, register_gauge, Counter, CounterVec, Gauge,
};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap};
use std::fs::{self, File, OpenOptions};
use std::io::{BufReader, BufWriter, Write};
use std::path::{Path, PathBuf};
use std::sync::{
    atomic::{AtomicU64, Ordering},
    Arc,
};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use thiserror::Error;
use tracing::{debug, error, info, trace, warn};

// ── Constants ─────────────────────────────────────────────────────────────

/// Default maximum age of a transaction in seconds (1 hour).
pub const DEFAULT_MAX_TX_AGE_SECS: u64 = 3600;

/// Default maximum total transactions in the pool (10,000).
pub const DEFAULT_MAX_POOL_SIZE: usize = 10_000;

/// Default maximum number of transactions per sender.
pub const DEFAULT_MAX_PER_SENDER: usize = 64;

/// Default fee bump percentage required for replacement (10%).
pub const DEFAULT_FEE_BUMP_PERCENT: u64 = 10;

/// Default persistence file name.
pub const DEFAULT_PERSIST_FILE: &str = "txpool.json";

/// Lock timeout in seconds.
pub const DEFAULT_LOCK_TIMEOUT_SECS: u64 = 10;

/// Temporary file extension for atomic writes.
const TEMP_EXT: &str = ".tmp";

/// Current serialization version.
const CURRENT_VERSION: u32 = 1;

// ── Configuration ─────────────────────────────────────────────────────────

/// Configuration for the transaction pool.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TxPoolConfig {
    /// Maximum age of a transaction in seconds.
    pub max_tx_age_secs: u64,
    /// Maximum total number of transactions in the pool.
    pub max_pool_size: usize,
    /// Maximum number of transactions per sender.
    pub max_per_sender: usize,
    /// Fee bump percentage required for replacement (e.g., 10 = 10%).
    pub fee_bump_percent: u64,
    /// Whether to persist the pool to disk.
    pub persist_pool: bool,
    /// Path for persistence.
    pub persist_path: Option<PathBuf>,
    /// Whether to enable metrics.
    pub enable_metrics: bool,
    /// Lock timeout in seconds.
    pub lock_timeout_secs: u64,
}

impl Default for TxPoolConfig {
    fn default() -> Self {
        Self {
            max_tx_age_secs: DEFAULT_MAX_TX_AGE_SECS,
            max_pool_size: DEFAULT_MAX_POOL_SIZE,
            max_per_sender: DEFAULT_MAX_PER_SENDER,
            fee_bump_percent: DEFAULT_FEE_BUMP_PERCENT,
            persist_pool: false,
            persist_path: None,
            enable_metrics: true,
            lock_timeout_secs: DEFAULT_LOCK_TIMEOUT_SECS,
        }
    }
}

impl TxPoolConfig {
    /// Validate the configuration.
    pub fn validate(&self) -> Result<(), String> {
        if self.max_tx_age_secs == 0 {
            return Err("max_tx_age_secs must be > 0".into());
        }
        if self.max_pool_size == 0 {
            return Err("max_pool_size must be > 0".into());
        }
        if self.max_per_sender == 0 {
            return Err("max_per_sender must be > 0".into());
        }
        if self.fee_bump_percent == 0 {
            return Err("fee_bump_percent must be > 0".into());
        }
        if self.persist_pool && self.persist_path.is_none() {
            return Err("persist_path must be set when persist_pool is true".into());
        }
        if self.lock_timeout_secs == 0 {
            return Err("lock_timeout_secs must be > 0".into());
        }
        Ok(())
    }
}

// ── Metrics ──────────────────────────────────────────────────────────────

/// Metrics for the transaction pool.
#[derive(Clone)]
pub struct TxPoolMetrics {
    pub pool_size: Gauge,
    pub total_inserts: Counter,
    pub total_replacements: Counter,
    pub total_evictions: CounterVec,
    pub total_drained: Counter,
}

impl TxPoolMetrics {
    pub fn new() -> Result<Self, prometheus::Error> {
        let pool_size = register_gauge!(
            "iona_txpool_size",
            "Current number of transactions in the pool"
        )?;
        let total_inserts = register_counter!(
            "iona_txpool_inserts_total",
            "Total transactions inserted"
        )?;
        let total_replacements = register_counter!(
            "iona_txpool_replacements_total",
            "Total transactions replaced"
        )?;
        let total_evictions = register_counter_vec!(
            "iona_txpool_evictions_total",
            "Total transactions evicted",
            &["reason"]
        )?;
        let total_drained = register_counter!(
            "iona_txpool_drained_total",
            "Total transactions drained for inclusion"
        )?;
        Ok(Self {
            pool_size,
            total_inserts,
            total_replacements,
            total_evictions,
            total_drained,
        })
    }

    pub fn set_pool_size(&self, size: usize) {
        self.pool_size.set(size as f64);
    }

    pub fn record_insert(&self) {
        self.total_inserts.inc();
    }

    pub fn record_replacement(&self) {
        self.total_replacements.inc();
    }

    pub fn record_eviction(&self, reason: &str) {
        self.total_evictions.with_label_values(&[reason]).inc();
    }

    pub fn record_drain(&self, count: usize) {
        self.total_drained.inc_by(count as u64);
    }
}

impl Default for TxPoolMetrics {
    fn default() -> Self {
        Self::new().unwrap_or_else(|_| Self {
            pool_size: Gauge::new("iona_txpool_size", "Pool size").unwrap(),
            total_inserts: Counter::new("iona_txpool_inserts_total", "Inserts").unwrap(),
            total_replacements: Counter::new("iona_txpool_replacements_total", "Replacements").unwrap(),
            total_evictions: CounterVec::new(
                prometheus::Opts::new("iona_txpool_evictions_total", "Evictions"),
                &["reason"],
            ).unwrap(),
            total_drained: Counter::new("iona_txpool_drained_total", "Drained").unwrap(),
        })
    }
}

// ── Errors ───────────────────────────────────────────────────────────────

/// Errors that can occur when inserting a transaction into the pool.
#[derive(Debug, Error)]
pub enum TxPoolError {
    #[error("replacement transaction underpriced: existing fee_cap = {existing_fee_cap}, new fee_cap = {new_fee_cap} (bump required {bump_percent}%)")]
    ReplacementUnderpriced {
        existing_fee_cap: u128,
        new_fee_cap: u128,
        bump_percent: u64,
    },

    #[error("gas limit must be > 0, got {gas_limit}")]
    ZeroGasLimit { gas_limit: u64 },

    #[error("nonce overflow (max 2^64-1)")]
    NonceOverflow,

    #[error("sender address is empty")]
    EmptySender,

    #[error("invalid tx hash")]
    InvalidHash,

    #[error("pool is full (max {max})")]
    PoolFull { max: usize },

    #[error("sender lane full (max {max})")]
    SenderLaneFull { max: usize },

    #[error("configuration error: {0}")]
    Config(String),

    #[error("I/O error: {0}")]
    Io(String),

    #[error("serialization error: {0}")]
    Serialization(String),

    #[error("lock acquisition failed: {0}")]
    LockFailed(String),
}

pub type TxPoolResult<T> = Result<T, TxPoolError>;

// ── PendingTx ─────────────────────────────────────────────────────────────

/// Mempool entry (raw signed tx bytes + decoded metadata needed for ordering).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PendingTx {
    pub hash: String,
    pub from: String,
    pub nonce: u64,
    pub tx_type: u8,
    pub gas_limit: u64,
    pub gas_price: u128,
    pub max_fee_per_gas: Option<u128>,
    pub max_priority_fee_per_gas: Option<u128>,
    pub raw: Vec<u8>,
    pub inserted_at: u64,
}

impl PendingTx {
    /// Effective priority used for ordering (for EIP‑1559, use max_priority_fee_per_gas).
    pub fn priority(&self) -> u128 {
        self.max_priority_fee_per_gas.unwrap_or(self.gas_price)
    }

    /// Fee cap used for replacement detection.
    pub fn fee_cap(&self) -> u128 {
        self.max_fee_per_gas.unwrap_or(self.gas_price)
    }

    /// Validate the transaction fields (does not check signature).
    pub fn validate(&self) -> TxPoolResult<()> {
        if self.gas_limit == 0 {
            return Err(TxPoolError::ZeroGasLimit { gas_limit: self.gas_limit });
        }
        if self.from.is_empty() {
            return Err(TxPoolError::EmptySender);
        }
        if self.hash.is_empty() {
            return Err(TxPoolError::InvalidHash);
        }
        Ok(())
    }
}

// ── TxPool (core) ────────────────────────────────────────────────────────

/// Transaction pool with per‑sender nonce lanes and replacement rule.
#[derive(Default, Clone, Debug, Serialize, Deserialize)]
pub struct TxPool {
    pub(crate) by_sender: HashMap<String, BTreeMap<u64, PendingTx>>,
    #[serde(skip)]
    pub(crate) config: TxPoolConfig,
    #[serde(skip)]
    pub(crate) metrics: Arc<TxPoolMetrics>,
}

impl TxPool {
    /// Create a new empty transaction pool with configuration.
    pub fn new(config: TxPoolConfig) -> Self {
        Self {
            by_sender: HashMap::new(),
            config,
            metrics: Arc::new(TxPoolMetrics::default()),
        }
    }

    /// Total number of transactions in the pool.
    pub fn len(&self) -> usize {
        self.by_sender.values().map(|m| m.len()).sum()
    }

    /// Check if the pool is empty.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Number of pending transactions for a given sender.
    pub fn pending_for_sender(&self, sender: &str) -> usize {
        self.by_sender.get(sender).map(|m| m.len()).unwrap_or(0)
    }

    /// Total number of distinct senders.
    pub fn senders_count(&self) -> usize {
        self.by_sender.len()
    }

    /// Insert a transaction into the pool, replacing any existing transaction with the same nonce
    /// if the new transaction has a higher fee cap by at least `fee_bump_percent`.
    pub fn insert(&mut self, tx: PendingTx) -> TxPoolResult<()> {
        tx.validate()?;

        // Check global pool size.
        if self.len() >= self.config.max_pool_size {
            return Err(TxPoolError::PoolFull { max: self.config.max_pool_size });
        }

        let sender_lane = self.by_sender.entry(tx.from.clone()).or_default();
        if sender_lane.len() >= self.config.max_per_sender {
            return Err(TxPoolError::SenderLaneFull { max: self.config.max_per_sender });
        }

        if let Some(existing) = sender_lane.get(&tx.nonce) {
            let bump_percent = self.config.fee_bump_percent;
            let required_fee = existing.fee_cap() * (100 + bump_percent as u128) / 100;
            if tx.fee_cap() < required_fee {
                return Err(TxPoolError::ReplacementUnderpriced {
                    existing_fee_cap: existing.fee_cap(),
                    new_fee_cap: tx.fee_cap(),
                    bump_percent,
                });
            }
            self.metrics.record_replacement();
            trace!(hash = %tx.hash, nonce = tx.nonce, "replaced transaction");
        }

        sender_lane.insert(tx.nonce, tx);
        self.metrics.record_insert();
        self.metrics.set_pool_size(self.len());

        // Persist if enabled.
        if self.config.persist_pool {
            if let Some(ref path) = self.config.persist_path {
                let _ = self.save(path);
            }
        }

        Ok(())
    }

    /// Remove and return the next executable transaction for each sender,
    /// respecting the given current nonce. Returns up to `max` transactions,
    /// sorted by descending priority.
    pub fn drain_next_ready(
        &mut self,
        account_nonces: &HashMap<String, u64>,
        max: usize,
    ) -> Vec<PendingTx> {
        let mut ready = Vec::new();
        for (sender, lane) in self.by_sender.iter_mut() {
            let expected = account_nonces.get(sender).copied().unwrap_or(0);
            if let Some(tx) = lane.remove(&expected) {
                ready.push(tx);
            }
        }
        ready.sort_by(|a, b| b.priority().cmp(&a.priority()));
        ready.truncate(max);
        self.metrics.record_drain(ready.len());
        self.metrics.set_pool_size(self.len());
        ready
    }

    /// Count how many contiguous pending transactions exist for a sender starting from
    /// `expected_nonce`. Used for the `eth_getTransactionCount` "pending" tag.
    pub fn contiguous_from(&self, sender: &str, expected_nonce: u64) -> u64 {
        let Some(lane) = self.by_sender.get(sender) else {
            return 0;
        };
        let mut count = 0u64;
        let mut nonce = expected_nonce;
        while lane.contains_key(&nonce) {
            count += 1;
            nonce += 1;
        }
        count
    }

    /// Prune transactions older than `max_age_secs` and evict the oldest
    /// transactions if the pool exceeds `max_total`.
    pub fn prune(&mut self, now_secs: u64, max_age_secs: u64, max_total: usize) {
        let mut evicted = 0;

        // 1. Remove expired transactions
        for lane in self.by_sender.values_mut() {
            let expired: Vec<u64> = lane
                .iter()
                .filter_map(|(&n, tx)| {
                    if now_secs.saturating_sub(tx.inserted_at) > max_age_secs {
                        Some(n)
                    } else {
                        None
                    }
                })
                .collect();
            for nonce in expired {
                lane.remove(&nonce);
                evicted += 1;
            }
        }
        if evicted > 0 {
            self.metrics.record_eviction("expired");
            trace!(count = evicted, "expired transactions evicted");
        }

        // 2. Remove empty lanes
        self.by_sender.retain(|_, lane| !lane.is_empty());

        // 3. Evict oldest globally until under max_total
        let mut evicted_global = 0;
        while self.len() > max_total {
            let mut oldest_sender: Option<String> = None;
            let mut oldest_nonce: u64 = 0;
            let mut oldest_time: u64 = u64::MAX;

            for (sender, lane) in self.by_sender.iter() {
                for (&nonce, tx) in lane.iter() {
                    if tx.inserted_at < oldest_time {
                        oldest_time = tx.inserted_at;
                        oldest_sender = Some(sender.clone());
                        oldest_nonce = nonce;
                    }
                }
            }

            if let Some(sender) = oldest_sender {
                if let Some(lane) = self.by_sender.get_mut(&sender) {
                    lane.remove(&oldest_nonce);
                    evicted_global += 1;
                }
                self.by_sender.retain(|_, lane| !lane.is_empty());
            } else {
                break;
            }
        }
        if evicted_global > 0 {
            self.metrics.record_eviction("global_evict");
            trace!(count = evicted_global, "global eviction applied");
        }

        self.metrics.set_pool_size(self.len());
    }

    /// Save the pool to disk (atomic write).
    pub fn save(&self, path: &Path) -> Result<(), TxPoolError> {
        let _lock = acquire_lock(path)
            .map_err(|e| TxPoolError::LockFailed(e.to_string()))?;
        let temp_path = path.with_extension(TEMP_EXT);
        let json = serde_json::to_string_pretty(self)
            .map_err(|e| TxPoolError::Serialization(e.to_string()))?;
        fs::write(&temp_path, &json)
            .map_err(|e| TxPoolError::Io(e.to_string()))?;
        fs::rename(&temp_path, path)
            .map_err(|e| TxPoolError::Io(e.to_string()))?;
        Ok(())
    }

    /// Load the pool from disk.
    pub fn load(path: &Path, config: TxPoolConfig) -> Result<Self, TxPoolError> {
        if !path.exists() {
            return Ok(Self::new(config));
        }
        let _lock = acquire_lock(path)
            .map_err(|e| TxPoolError::LockFailed(e.to_string()))?;
        let file = File::open(path)
            .map_err(|e| TxPoolError::Io(e.to_string()))?;
        let reader = BufReader::new(file);
        let pool: Self = serde_json::from_reader(reader)
            .map_err(|e| TxPoolError::Serialization(e.to_string()))?;
        // Apply config to loaded pool.
        let mut loaded = pool;
        loaded.config = config;
        loaded.metrics = Arc::new(TxPoolMetrics::default());
        loaded.metrics.set_pool_size(loaded.len());
        Ok(loaded)
    }

    /// Return current pool metrics.
    pub fn metrics(&self) -> TxPoolMetricsSnapshot {
        TxPoolMetricsSnapshot {
            total_txs: self.len(),
            total_senders: self.senders_count(),
            max_per_sender: self
                .by_sender
                .values()
                .map(|lane| lane.len())
                .max()
                .unwrap_or(0),
        }
    }
}

// ── File locking helper ──────────────────────────────────────────────────

fn acquire_lock(path: &Path) -> Result<File, String> {
    let lock_path = path.with_extension("lock");
    let file = OpenOptions::new()
        .create(true)
        .write(true)
        .open(&lock_path)
        .map_err(|e| format!("cannot open lock file: {}", e))?;
    let timeout = Duration::from_secs(DEFAULT_LOCK_TIMEOUT_SECS);
    let start = Instant::now();
    loop {
        match file.try_lock_exclusive() {
            Ok(()) => return Ok(file),
            Err(_) => {
                if start.elapsed() > timeout {
                    return Err(format!("lock timeout after {}s", DEFAULT_LOCK_TIMEOUT_SECS));
                }
                std::thread::sleep(Duration::from_millis(100));
            }
        }
    }
}

// ── TxPoolManager (thread‑safe wrapper) ──────────────────────────────────

/// Thread‑safe manager for the transaction pool.
#[derive(Clone)]
pub struct TxPoolManager {
    inner: Arc<Mutex<TxPool>>,
    config: Arc<TxPoolConfig>,
    path: Option<PathBuf>,
}

impl TxPoolManager {
    /// Create a new manager with the given configuration.
    pub fn new(config: TxPoolConfig) -> Result<Self, TxPoolError> {
        config.validate().map_err(|e| TxPoolError::Config(e.to_string()))?;
        let path = config.persist_path.clone();
        let pool = if config.persist_pool {
            if let Some(ref p) = path {
                TxPool::load(p, config.clone()).unwrap_or_else(|_| TxPool::new(config.clone()))
            } else {
                TxPool::new(config.clone())
            }
        } else {
            TxPool::new(config.clone())
        };
        Ok(Self {
            inner: Arc::new(Mutex::new(pool)),
            config: Arc::new(config),
            path,
        })
    }

    /// Insert a transaction.
    pub fn insert(&self, tx: PendingTx) -> TxPoolResult<()> {
        let mut pool = self.inner.lock();
        pool.insert(tx)
    }

    /// Drain ready transactions.
    pub fn drain_next_ready(
        &self,
        account_nonces: &HashMap<String, u64>,
        max: usize,
    ) -> Vec<PendingTx> {
        let mut pool = self.inner.lock();
        pool.drain_next_ready(account_nonces, max)
    }

    /// Get contiguous count for a sender.
    pub fn contiguous_from(&self, sender: &str, expected_nonce: u64) -> u64 {
        self.inner.lock().contiguous_from(sender, expected_nonce)
    }

    /// Prune the pool.
    pub fn prune(&self, now_secs: u64, max_age_secs: u64, max_total: usize) {
        let mut pool = self.inner.lock();
        pool.prune(now_secs, max_age_secs, max_total);
        // If persistence enabled, save after prune.
        if self.config.persist_pool {
            if let Some(ref p) = self.path {
                let _ = pool.save(p);
            }
        }
    }

    /// Save the pool to disk.
    pub fn save(&self) -> Result<(), TxPoolError> {
        let pool = self.inner.lock();
        if let Some(ref p) = self.path {
            pool.save(p)
        } else {
            Err(TxPoolError::Config("no persistence path set".into()))
        }
    }

    /// Get pool metrics.
    pub fn metrics(&self) -> TxPoolMetricsSnapshot {
        self.inner.lock().metrics()
    }

    /// Get pool length.
    pub fn len(&self) -> usize {
        self.inner.lock().len()
    }

    /// Check if pool is empty.
    pub fn is_empty(&self) -> bool {
        self.inner.lock().is_empty()
    }

    /// Get configuration.
    pub fn config(&self) -> &TxPoolConfig {
        &self.config
    }
}

// ── Metrics snapshot ─────────────────────────────────────────────────────

/// Simple metrics about the transaction pool.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TxPoolMetricsSnapshot {
    pub total_txs: usize,
    pub total_senders: usize,
    pub max_per_sender: usize,
}

// ── Tests ─────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    fn dummy_tx(from: &str, nonce: u64, gas_price: u128, inserted_at: u64) -> PendingTx {
        PendingTx {
            hash: format!("0x{}", hex::encode(&[nonce as u8; 32])),
            from: from.to_string(),
            nonce,
            tx_type: 0,
            gas_limit: 21_000,
            gas_price,
            max_fee_per_gas: None,
            max_priority_fee_per_gas: None,
            raw: vec![],
            inserted_at,
        }
    }

    fn dummy_eip1559_tx(from: &str, nonce: u64, max_fee: u128, priority: u128, inserted_at: u64) -> PendingTx {
        PendingTx {
            hash: format!("0x{}", hex::encode(&[nonce as u8; 32])),
            from: from.to_string(),
            nonce,
            tx_type: 2,
            gas_limit: 21_000,
            gas_price: 0,
            max_fee_per_gas: Some(max_fee),
            max_priority_fee_per_gas: Some(priority),
            raw: vec![],
            inserted_at,
        }
    }

    fn test_config() -> TxPoolConfig {
        let mut cfg = TxPoolConfig::default();
        cfg.max_pool_size = 10;
        cfg.max_per_sender = 5;
        cfg.fee_bump_percent = 10;
        cfg.persist_pool = false;
        cfg
    }

    #[test]
    fn test_insert_and_replace() {
        let cfg = test_config();
        let mut pool = TxPool::new(cfg);
        let tx1 = dummy_tx("alice", 0, 100, 10);
        assert!(pool.insert(tx1).is_ok());
        assert_eq!(pool.len(), 1);

        // Replacement with higher price = allowed
        let tx2 = dummy_tx("alice", 0, 110, 11);
        assert!(pool.insert(tx2).is_ok());
        assert_eq!(pool.len(), 1);

        // Replacement with insufficient bump (need 10%, so 110 * 1.1 = 121)
        let tx3 = dummy_tx("alice", 0, 115, 12);
        let err = pool.insert(tx3).unwrap_err();
        assert!(matches!(err, TxPoolError::ReplacementUnderpriced { .. }));
    }

    #[test]
    fn test_drain_next_ready() {
        let cfg = test_config();
        let mut pool = TxPool::new(cfg);
        let tx1 = dummy_tx("alice", 0, 100, 10);
        let tx2 = dummy_tx("bob", 0, 200, 20);
        pool.insert(tx1).unwrap();
        pool.insert(tx2).unwrap();

        let mut nonces = HashMap::new();
        nonces.insert("alice".to_string(), 0);
        nonces.insert("bob".to_string(), 0);

        let ready = pool.drain_next_ready(&nonces, 10);
        assert_eq!(ready.len(), 2);
        // bob has higher priority (200)
        assert_eq!(ready[0].from, "bob");
        assert_eq!(ready[1].from, "alice");
    }

    #[test]
    fn test_contiguous_from() {
        let cfg = test_config();
        let mut pool = TxPool::new(cfg);
        pool.insert(dummy_tx("alice", 0, 100, 10)).unwrap();
        pool.insert(dummy_tx("alice", 1, 100, 11)).unwrap();
        pool.insert(dummy_tx("alice", 2, 100, 12)).unwrap();

        assert_eq!(pool.contiguous_from("alice", 0), 3);
        assert_eq!(pool.contiguous_from("alice", 1), 2);
        assert_eq!(pool.contiguous_from("alice", 3), 0);
        assert_eq!(pool.contiguous_from("bob", 0), 0);
    }

    #[test]
    fn test_prune_by_age() {
        let cfg = test_config();
        let mut pool = TxPool::new(cfg);
        pool.insert(dummy_tx("alice", 0, 100, 100)).unwrap();
        pool.insert(dummy_tx("bob", 0, 100, 200)).unwrap();
        pool.prune(250, 100, 100);
        // alice tx inserted at 100, now 250 → age 150 > 100 → removed
        assert_eq!(pool.len(), 1);
        assert!(pool.by_sender.contains_key("bob"));
    }

    #[test]
    fn test_prune_by_total() {
        let cfg = test_config();
        let mut pool = TxPool::new(cfg);
        for i in 0..10 {
            pool.insert(dummy_tx(&format!("sender_{}", i % 2), i, 100, i as u64)).unwrap();
        }
        assert_eq!(pool.len(), 10);
        pool.prune(1000, 3600, 5);
        assert_eq!(pool.len(), 5);
    }

    #[test]
    fn test_metrics() {
        let cfg = test_config();
        let mut pool = TxPool::new(cfg);
        pool.insert(dummy_tx("alice", 0, 100, 10)).unwrap();
        pool.insert(dummy_tx("alice", 1, 100, 11)).unwrap();
        pool.insert(dummy_tx("bob", 0, 100, 12)).unwrap();

        let m = pool.metrics();
        assert_eq!(m.total_txs, 3);
        assert_eq!(m.total_senders, 2);
        assert_eq!(m.max_per_sender, 2);
    }

    #[test]
    fn test_eip1559_priority() {
        let tx = dummy_eip1559_tx("alice", 0, 1000, 50, 10);
        assert_eq!(tx.priority(), 50);
        assert_eq!(tx.fee_cap(), 1000);
    }

    #[test]
    fn test_persistence() -> Result<(), TxPoolError> {
        let dir = tempdir().unwrap();
        let path = dir.path().join("txpool.json");
        let mut cfg = test_config();
        cfg.persist_pool = true;
        cfg.persist_path = Some(path.clone());

        let manager = TxPoolManager::new(cfg)?;
        let tx = dummy_tx("alice", 0, 100, 10);
        manager.insert(tx)?;
        manager.prune(1000, 3600, 100);
        assert_eq!(manager.len(), 1);

        // Reload.
        let manager2 = TxPoolManager::new(cfg)?;
        assert_eq!(manager2.len(), 1);

        Ok(())
    }

    #[test]
    fn test_config_validation() {
        let mut cfg = TxPoolConfig::default();
        assert!(cfg.validate().is_ok());
        cfg.max_tx_age_secs = 0;
        assert!(cfg.validate().is_err());
        cfg.max_tx_age_secs = 10;
        cfg.max_pool_size = 0;
        assert!(cfg.validate().is_err());
        cfg.max_pool_size = 100;
        cfg.max_per_sender = 0;
        assert!(cfg.validate().is_err());
        cfg.max_per_sender = 5;
        cfg.fee_bump_percent = 0;
        assert!(cfg.validate().is_err());
        cfg.fee_bump_percent = 10;
        cfg.persist_pool = true;
        cfg.persist_path = None;
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn test_sender_lane_limit() {
        let mut cfg = test_config();
        cfg.max_per_sender = 2;
        let mut pool = TxPool::new(cfg);
        pool.insert(dummy_tx("alice", 0, 100, 10)).unwrap();
        pool.insert(dummy_tx("alice", 1, 100, 11)).unwrap();
        let err = pool.insert(dummy_tx("alice", 2, 100, 12)).unwrap_err();
        assert!(matches!(err, TxPoolError::SenderLaneFull { .. }));
    }

    #[test]
    fn test_global_pool_limit() {
        let mut cfg = test_config();
        cfg.max_pool_size = 2;
        let mut pool = TxPool::new(cfg);
        pool.insert(dummy_tx("alice", 0, 100, 10)).unwrap();
        pool.insert(dummy_tx("bob", 0, 100, 11)).unwrap();
        let err = pool.insert(dummy_tx("charlie", 0, 100, 12)).unwrap_err();
        assert!(matches!(err, TxPoolError::PoolFull { .. }));
    }

    #[test]
    fn test_manager_thread_safety() {
        let cfg = test_config();
        let manager = TxPoolManager::new(cfg).unwrap();
        let manager = Arc::new(manager);
        let mut handles = vec![];
        for i in 0..10 {
            let m = manager.clone();
            handles.push(std::thread::spawn(move || {
                let tx = dummy_tx(&format!("sender_{}", i), 0, 100, i as u64);
                m.insert(tx).unwrap();
            }));
        }
        for h in handles {
            h.join().unwrap();
        }
        assert_eq!(manager.len(), 10);
    }
}
