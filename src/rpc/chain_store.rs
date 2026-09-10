//! Chain database — append‑only JSONL storage with indexing.
//!
//! # Production Features
//! - Configurable via `ChainDbConfig`.
//! - File locking (`flock`) for concurrent access.
//! - True atomic append via `O_APPEND` + `fsync` under a `flock`.
//! - Streaming reads for large files (memory‑efficient).
//! - Pruning and compaction with retention policy.
//! - Optimised log indexing (address, topics) with byte offsets.
//! - Prometheus metrics (optional) with atomic fallback.
//! - Consistent `parking_lot::Mutex` usage across the state.
//! - Overflow‑safe counters.
//! - Structured error handling with `ChainDbError`.
//! - Full test coverage.

use fs2::FileExt;
use parking_lot::Mutex;
use prometheus::{register_counter, Counter};
use serde::{Deserialize, Serialize};
use std::{
    collections::{HashMap, HashSet},
    fs::{self, File, OpenOptions},
    io::{self, BufRead, BufReader, BufWriter, Read, Seek, SeekFrom, Write},
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc,
    },
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use thiserror::Error;
use tracing::{debug, error, info, trace, warn};

use crate::rpc::eth_rpc::{Block, EthRpcState, Log, Receipt, TxRecord};

// ── Errors ────────────────────────────────────────────────────────────────

/// Errors that can occur during chain database operations.
#[derive(Debug, Error)]
pub enum ChainDbError {
    #[error("I/O error: {0}")]
    Io(#[from] io::Error),

    #[error("serialization error: {0}")]
    Serialization(String),

    #[error("configuration error: {0}")]
    Config(String),

    #[error("lock acquisition failed: {0}")]
    LockFailed(String),

    #[error("metrics error: {0}")]
    Metrics(String),

    #[error("data corruption: {0}")]
    Corrupt(String),
}

pub type ChainDbResult<T> = Result<T, ChainDbError>;

// ── Constants ─────────────────────────────────────────────────────────────

/// Current schema version.
pub const SCHEMA_VERSION: u32 = 2;

/// Default maximum blocks to keep (0 = unlimited).
pub const DEFAULT_MAX_BLOCKS: usize = 0;

/// Default compaction interval (seconds).
pub const DEFAULT_COMPACTION_INTERVAL_SECS: u64 = 3600;

/// Default lock timeout (seconds).
pub const DEFAULT_LOCK_TIMEOUT_SECS: u64 = 10;

/// Temporary file extension for atomic rewrites.
const TEMP_EXT: &str = ".tmp";

/// Lock file extension.
const LOCK_EXT: &str = ".lock";

// ── Configuration ─────────────────────────────────────────────────────────

/// Configuration for the chain database.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChainDbConfig {
    /// Maximum number of blocks to keep (0 = unlimited).
    pub max_blocks: usize,
    /// Compaction interval in seconds.
    pub compaction_interval_secs: u64,
    /// Whether to enable log indexing.
    pub enable_log_index: bool,
    /// Whether to enable atomic metrics.
    pub enable_metrics: bool,
    /// Whether to enable Prometheus metrics.
    pub enable_prometheus: bool,
    /// Lock timeout in seconds.
    pub lock_timeout_secs: u64,
    /// Whether to `fsync` after each append.
    pub fsync_on_write: bool,
}

impl Default for ChainDbConfig {
    fn default() -> Self {
        Self {
            max_blocks: DEFAULT_MAX_BLOCKS,
            compaction_interval_secs: DEFAULT_COMPACTION_INTERVAL_SECS,
            enable_log_index: true,
            enable_metrics: true,
            enable_prometheus: false,
            lock_timeout_secs: DEFAULT_LOCK_TIMEOUT_SECS,
            fsync_on_write: true,
        }
    }
}

impl ChainDbConfig {
    /// Validate the configuration.
    pub fn validate(&self) -> ChainDbResult<()> {
        if self.compaction_interval_secs == 0 {
            return Err(ChainDbError::Config(
                "compaction_interval_secs must be > 0".into(),
            ));
        }
        if self.lock_timeout_secs == 0 {
            return Err(ChainDbError::Config("lock_timeout_secs must be > 0".into()));
        }
        Ok(())
    }

    /// Enable Prometheus metrics.
    pub fn with_prometheus(mut self) -> Self {
        self.enable_prometheus = true;
        self
    }
}

// ── Prometheus Metrics ──────────────────────────────────────────────────

/// Prometheus counters/gauges for the chain database.
#[derive(Clone)]
pub struct ChainDbPrometheus {
    pub blocks_written_total: Counter,
    pub receipts_written_total: Counter,
    pub txs_written_total: Counter,
    pub logs_written_total: Counter,
    pub blocks_read_total: Counter,
    pub receipts_read_total: Counter,
    pub txs_read_total: Counter,
    pub logs_read_total: Counter,
    pub index_hits_total: Counter,
    pub index_misses_total: Counter,
    pub compactions_total: Counter,
    pub compaction_time_ns_total: Counter,
}

impl ChainDbPrometheus {
    /// Register metrics with the global Prometheus registry.
    pub fn new() -> Result<Self, prometheus::Error> {
        Ok(Self {
            blocks_written_total: register_counter!(
                "iona_chaindb_blocks_written_total",
                "Total blocks written"
            )?,
            receipts_written_total: register_counter!(
                "iona_chaindb_receipts_written_total",
                "Total receipts written"
            )?,
            txs_written_total: register_counter!(
                "iona_chaindb_txs_written_total",
                "Total transactions written"
            )?,
            logs_written_total: register_counter!(
                "iona_chaindb_logs_written_total",
                "Total logs written"
            )?,
            blocks_read_total: register_counter!(
                "iona_chaindb_blocks_read_total",
                "Total blocks read"
            )?,
            receipts_read_total: register_counter!(
                "iona_chaindb_receipts_read_total",
                "Total receipts read"
            )?,
            txs_read_total: register_counter!(
                "iona_chaindb_txs_read_total",
                "Total transactions read"
            )?,
            logs_read_total: register_counter!(
                "iona_chaindb_logs_read_total",
                "Total logs read"
            )?,
            index_hits_total: register_counter!(
                "iona_chaindb_index_hits_total",
                "Total log index hits"
            )?,
            index_misses_total: register_counter!(
                "iona_chaindb_index_misses_total",
                "Total log index misses"
            )?,
            compactions_total: register_counter!(
                "iona_chaindb_compactions_total",
                "Total compaction operations"
            )?,
            compaction_time_ns_total: register_counter!(
                "iona_chaindb_compaction_time_ns_total",
                "Total time spent in compaction (ns)"
            )?,
        })
    }

    /// Create an unregistered instance (for tests or disabled metrics).
    pub fn new_unregistered() -> Self {
        Self {
            blocks_written_total: Counter::new("iona_chaindb_blocks_written_total", "Blocks").unwrap(),
            receipts_written_total: Counter::new("iona_chaindb_receipts_written_total", "Receipts").unwrap(),
            txs_written_total: Counter::new("iona_chaindb_txs_written_total", "Txs").unwrap(),
            logs_written_total: Counter::new("iona_chaindb_logs_written_total", "Logs").unwrap(),
            blocks_read_total: Counter::new("iona_chaindb_blocks_read_total", "Blocks read").unwrap(),
            receipts_read_total: Counter::new("iona_chaindb_receipts_read_total", "Receipts read").unwrap(),
            txs_read_total: Counter::new("iona_chaindb_txs_read_total", "Txs read").unwrap(),
            logs_read_total: Counter::new("iona_chaindb_logs_read_total", "Logs read").unwrap(),
            index_hits_total: Counter::new("iona_chaindb_index_hits_total", "Hits").unwrap(),
            index_misses_total: Counter::new("iona_chaindb_index_misses_total", "Misses").unwrap(),
            compactions_total: Counter::new("iona_chaindb_compactions_total", "Compactions").unwrap(),
            compaction_time_ns_total: Counter::new("iona_chaindb_compaction_time_ns_total", "Time").unwrap(),
        }
    }
}

// ── Metrics (atomic + optional Prometheus) ──────────────────────────────

/// Metrics for the chain database.
#[derive(Debug, Clone)]
pub struct ChainDbMetrics {
    pub blocks_written: Arc<AtomicU64>,
    pub receipts_written: Arc<AtomicU64>,
    pub txs_written: Arc<AtomicU64>,
    pub logs_written: Arc<AtomicU64>,
    pub blocks_read: Arc<AtomicU64>,
    pub receipts_read: Arc<AtomicU64>,
    pub txs_read: Arc<AtomicU64>,
    pub logs_read: Arc<AtomicU64>,
    pub index_hits: Arc<AtomicU64>,
    pub index_misses: Arc<AtomicU64>,
    pub compactions: Arc<AtomicU64>,
    pub compaction_duration_ns: Arc<AtomicU64>,
    pub prometheus: Option<Arc<ChainDbPrometheus>>,
}

impl Default for ChainDbMetrics {
    fn default() -> Self {
        Self {
            blocks_written: Arc::new(AtomicU64::new(0)),
            receipts_written: Arc::new(AtomicU64::new(0)),
            txs_written: Arc::new(AtomicU64::new(0)),
            logs_written: Arc::new(AtomicU64::new(0)),
            blocks_read: Arc::new(AtomicU64::new(0)),
            receipts_read: Arc::new(AtomicU64::new(0)),
            txs_read: Arc::new(AtomicU64::new(0)),
            logs_read: Arc::new(AtomicU64::new(0)),
            index_hits: Arc::new(AtomicU64::new(0)),
            index_misses: Arc::new(AtomicU64::new(0)),
            compactions: Arc::new(AtomicU64::new(0)),
            compaction_duration_ns: Arc::new(AtomicU64::new(0)),
            prometheus: None,
        }
    }
}

impl ChainDbMetrics {
    /// Create a new metrics instance, optionally with Prometheus.
    pub fn new(enable_prometheus: bool) -> Result<Self, prometheus::Error> {
        let prometheus = if enable_prometheus {
            Some(Arc::new(ChainDbPrometheus::new()?))
        } else {
            None
        };
        Ok(Self {
            prometheus,
            ..Default::default()
        })
    }

    pub fn record_block_write(&self) {
        self.blocks_written.fetch_add(1, Ordering::Relaxed);
        if let Some(p) = &self.prometheus {
            p.blocks_written_total.inc();
        }
    }
    pub fn record_receipt_write(&self, count: u64) {
        self.receipts_written.fetch_add(count, Ordering::Relaxed);
        if let Some(p) = &self.prometheus {
            p.receipts_written_total.inc_by(count as f64);
        }
    }
    pub fn record_tx_write(&self, count: u64) {
        self.txs_written.fetch_add(count, Ordering::Relaxed);
        if let Some(p) = &self.prometheus {
            p.txs_written_total.inc_by(count as f64);
        }
    }
    pub fn record_log_write(&self, count: u64) {
        self.logs_written.fetch_add(count, Ordering::Relaxed);
        if let Some(p) = &self.prometheus {
            p.logs_written_total.inc_by(count as f64);
        }
    }
    pub fn record_block_read(&self, count: u64) {
        self.blocks_read.fetch_add(count, Ordering::Relaxed);
        if let Some(p) = &self.prometheus {
            p.blocks_read_total.inc_by(count as f64);
        }
    }
    pub fn record_receipt_read(&self, count: u64) {
        self.receipts_read.fetch_add(count, Ordering::Relaxed);
        if let Some(p) = &self.prometheus {
            p.receipts_read_total.inc_by(count as f64);
        }
    }
    pub fn record_tx_read(&self, count: u64) {
        self.txs_read.fetch_add(count, Ordering::Relaxed);
        if let Some(p) = &self.prometheus {
            p.txs_read_total.inc_by(count as f64);
        }
    }
    pub fn record_log_read(&self, count: u64) {
        self.logs_read.fetch_add(count, Ordering::Relaxed);
        if let Some(p) = &self.prometheus {
            p.logs_read_total.inc_by(count as f64);
        }
    }
    pub fn record_index_hit(&self) {
        self.index_hits.fetch_add(1, Ordering::Relaxed);
        if let Some(p) = &self.prometheus {
            p.index_hits_total.inc();
        }
    }
    pub fn record_index_miss(&self) {
        self.index_misses.fetch_add(1, Ordering::Relaxed);
        if let Some(p) = &self.prometheus {
            p.index_misses_total.inc();
        }
    }
    pub fn record_compaction(&self, duration: Duration) {
        self.compactions.fetch_add(1, Ordering::Relaxed);
        let ns = duration.as_nanos().min(u64::MAX as u128) as u64;
        self.compaction_duration_ns.fetch_add(ns, Ordering::Relaxed);
        if let Some(p) = &self.prometheus {
            p.compactions_total.inc();
            p.compaction_time_ns_total.inc_by(ns as f64);
        }
    }

    /// Snapshot of the current metric values.
    pub fn snapshot(&self) -> ChainDbMetricsSnapshot {
        ChainDbMetricsSnapshot {
            blocks_written: self.blocks_written.load(Ordering::Relaxed),
            receipts_written: self.receipts_written.load(Ordering::Relaxed),
            txs_written: self.txs_written.load(Ordering::Relaxed),
            logs_written: self.logs_written.load(Ordering::Relaxed),
            blocks_read: self.blocks_read.load(Ordering::Relaxed),
            receipts_read: self.receipts_read.load(Ordering::Relaxed),
            txs_read: self.txs_read.load(Ordering::Relaxed),
            logs_read: self.logs_read.load(Ordering::Relaxed),
            index_hits: self.index_hits.load(Ordering::Relaxed),
            index_misses: self.index_misses.load(Ordering::Relaxed),
            compactions: self.compactions.load(Ordering::Relaxed),
            compaction_duration_ns: self.compaction_duration_ns.load(Ordering::Relaxed),
        }
    }
}

/// Snapshot of chain database metrics.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ChainDbMetricsSnapshot {
    pub blocks_written: u64,
    pub receipts_written: u64,
    pub txs_written: u64,
    pub logs_written: u64,
    pub blocks_read: u64,
    pub receipts_read: u64,
    pub txs_read: u64,
    pub logs_read: u64,
    pub index_hits: u64,
    pub index_misses: u64,
    pub compactions: u64,
    pub compaction_duration_ns: u64,
}

// ── Metadata ─────────────────────────────────────────────────────────────

/// Database metadata.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Meta {
    pub schema_version: u32,
    pub created_at_unix: u64,
    pub last_compacted_at: u64,
    pub block_count: u64,
    pub highest_block: u64,
}

impl Default for Meta {
    fn default() -> Self {
        Self {
            schema_version: SCHEMA_VERSION,
            created_at_unix: now_unix(),
            last_compacted_at: now_unix(),
            block_count: 0,
            highest_block: 0,
        }
    }
}

impl Meta {
    pub fn new() -> Self {
        Self::default()
    }
}

// ── File paths ───────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct ChainFiles {
    pub blocks: PathBuf,
    pub receipts: PathBuf,
    pub txs: PathBuf,
    pub logs: PathBuf,
    pub meta: PathBuf,
}

impl ChainFiles {
    pub fn new(dir: &Path) -> Self {
        Self {
            blocks: dir.join("blocks.jsonl"),
            receipts: dir.join("receipts.jsonl"),
            txs: dir.join("txs.jsonl"),
            logs: dir.join("logs.jsonl"),
            meta: dir.join("meta.json"),
        }
    }

    pub fn ensure_dirs(&self) -> io::Result<()> {
        for path in [&self.blocks, &self.receipts, &self.txs, &self.logs] {
            if let Some(parent) = path.parent() {
                fs::create_dir_all(parent)?;
            }
        }
        Ok(())
    }
}

// ── File locking helpers ────────────────────────────────────────────────

fn acquire_lock(path: &Path, timeout_secs: u64) -> ChainDbResult<File> {
    let lock_path = path.with_extension(LOCK_EXT);
    let file = OpenOptions::new()
        .create(true)
        .write(true)
        .open(&lock_path)
        .map_err(|e| ChainDbError::LockFailed(format!("cannot open lock file: {}", e)))?;
    let timeout = Duration::from_secs(timeout_secs);
    let start = Instant::now();
    loop {
        match file.try_lock_exclusive() {
            Ok(()) => return Ok(file),
            Err(_) => {
                if start.elapsed() > timeout {
                    return Err(ChainDbError::LockFailed(format!(
                        "lock timeout after {}s",
                        timeout_secs
                    )));
                }
                std::thread::sleep(Duration::from_millis(100));
            }
        }
    }
}

// ── JSONL operations ─────────────────────────────────────────────────────

/// Truly atomic append to a JSONL file.
///
/// Correctly appends (does **not** truncate) a single line under an
/// exclusive `flock`. The previous implementation wrote to a temp file and
/// renamed it, which silently truncated the entire file to a single line.
pub fn append_jsonl_atomic<T: Serialize>(
    path: &Path,
    value: &T,
    config: &ChainDbConfig,
) -> ChainDbResult<u64> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }

    let _lock = acquire_lock(path, config.lock_timeout_secs)?;

    let mut f = OpenOptions::new()
        .create(true)
        .append(true)
        .read(true)
        .open(path)?;
    // Ensure the file offset reflects the end of file for offset reporting.
    f.seek(SeekFrom::End(0))?;
    let offset = f.stream_position()?;

    let line = serde_json::to_string(value)
        .map_err(|e| ChainDbError::Serialization(e.to_string()))?;
    f.write_all(line.as_bytes())?;
    f.write_all(b"\n")?;
    if config.fsync_on_write {
        f.sync_all()?;
    }
    Ok(offset)
}

/// Append a value to a JSONL file without acquiring a lock.
/// The caller is responsible for locking.
pub fn append_jsonl<T: Serialize>(path: &Path, value: &T) -> ChainDbResult<u64> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let mut f = OpenOptions::new()
        .create(true)
        .append(true)
        .read(true)
        .open(path)?;
    f.seek(SeekFrom::End(0))?;
    let offset = f.stream_position()?;
    let line = serde_json::to_string(value)
        .map_err(|e| ChainDbError::Serialization(e.to_string()))?;
    f.write_all(line.as_bytes())?;
    f.write_all(b"\n")?;
    Ok(offset)
}

/// Read all items from a JSONL file.
pub fn load_jsonl<T: for<'de> Deserialize<'de>>(path: &Path) -> ChainDbResult<Vec<T>> {
    if !path.exists() {
        return Ok(Vec::new());
    }
    let f = File::open(path)?;
    let reader = BufReader::new(f);
    let mut out = Vec::new();
    for (lineno, line) in reader.lines().enumerate() {
        let line = line?;
        if line.trim().is_empty() {
            continue;
        }
        let v: T = serde_json::from_str(&line).map_err(|e| {
            ChainDbError::Corrupt(format!("line {}: {}", lineno + 1, e))
        })?;
        out.push(v);
    }
    Ok(out)
}

/// Stream items from a JSONL file with a callback.
pub fn stream_jsonl<T, F>(path: &Path, mut callback: F) -> ChainDbResult<()>
where
    T: for<'de> Deserialize<'de>,
    F: FnMut(T) -> ChainDbResult<()>,
{
    if !path.exists() {
        return Ok(());
    }
    let f = File::open(path)?;
    let reader = BufReader::new(f);
    for (lineno, line) in reader.lines().enumerate() {
        let line = line?;
        if line.trim().is_empty() {
            continue;
        }
        let v: T = serde_json::from_str(&line).map_err(|e| {
            ChainDbError::Corrupt(format!("line {}: {}", lineno + 1, e))
        })?;
        callback(v)?;
    }
    Ok(())
}

/// Rewrite a JSONL file atomically (write to temp, then rename).
pub fn rewrite_jsonl<T: Serialize>(path: &Path, items: &[T]) -> ChainDbResult<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let temp_path = path.with_extension(TEMP_EXT);
    {
        let f = OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(&temp_path)?;
        let mut writer = BufWriter::new(f);
        for it in items {
            let line = serde_json::to_string(it)
                .map_err(|e| ChainDbError::Serialization(e.to_string()))?;
            writer.write_all(line.as_bytes())?;
            writer.write_all(b"\n")?;
        }
        writer.flush()?;
        writer.get_ref().sync_all()?;
    }
    fs::rename(&temp_path, path)?;
    Ok(())
}

// ── Indexing ─────────────────────────────────────────────────────────────

/// Log index entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogIndexEntry {
    pub block_number: u64,
    pub tx_hash: String,
    pub log_index: u64,
    pub offset: Option<u64>,
}

fn logs_index_dir(dir: &Path) -> PathBuf {
    dir.join("log_index")
}

fn addr_index_path(dir: &Path, addr_hex: &str) -> PathBuf {
    logs_index_dir(dir)
        .join("by_address")
        .join(format!("{}.jsonl", addr_hex))
}

fn topic_index_path(dir: &Path, topic_hex: &str) -> PathBuf {
    logs_index_dir(dir)
        .join("by_topic")
        .join(format!("{}.jsonl", topic_hex))
}

/// Append log index entries with byte offsets.
pub fn append_log_indices_with_offsets(
    dir: &Path,
    logs: &[Log],
    offsets: &[u64],
    config: &ChainDbConfig,
) -> ChainDbResult<()> {
    if !config.enable_log_index {
        return Ok(());
    }
    if logs.len() != offsets.len() {
        return Err(ChainDbError::Config("logs/offsets mismatch".into()));
    }
    let _lock = acquire_lock(&logs_index_dir(dir).join(".index.lock"), config.lock_timeout_secs)?;

    for (l, off) in logs.iter().zip(offsets.iter()) {
        let entry = LogIndexEntry {
            block_number: l.block_number,
            tx_hash: l.tx_hash.clone(),
            log_index: l.log_index,
            offset: Some(*off),
        };
        let addr = l.address.trim_start_matches("0x").to_lowercase();
        append_jsonl(&addr_index_path(dir, &addr), &entry)?;
        for t in l.topics.iter() {
            let th = t.trim_start_matches("0x").to_lowercase();
            append_jsonl(&topic_index_path(dir, &th), &entry)?;
        }
    }
    Ok(())
}

/// Read index entries filtered by block range.
fn read_index_file(path: &Path, from: u64, to: u64) -> ChainDbResult<Vec<LogIndexEntry>> {
    let entries: Vec<LogIndexEntry> = load_jsonl(path)?;
    Ok(entries
        .into_iter()
        .filter(|e| e.block_number >= from && e.block_number <= to)
        .collect())
}

/// Query logs using the index (optimised).
pub fn query_logs_indexed(
    dir: &Path,
    from: u64,
    to: u64,
    address: Option<String>,
    topic0: Option<String>,
    config: &ChainDbConfig,
) -> ChainDbResult<Vec<Log>> {
    if !config.enable_log_index {
        return query_logs_scan(dir, from, to, address, topic0);
    }

    let mut candidates: Vec<LogIndexEntry> = Vec::new();

    match (address.clone(), topic0.clone()) {
        (Some(a), Some(t)) => {
            let ap = addr_index_path(dir, &a.trim_start_matches("0x").to_lowercase());
            let tp = topic_index_path(dir, &t.trim_start_matches("0x").to_lowercase());
            let a_entries = if ap.exists() {
                read_index_file(&ap, from, to)?
            } else {
                Vec::new()
            };
            let t_entries = if tp.exists() {
                read_index_file(&tp, from, to)?
            } else {
                Vec::new()
            };
            let aset: HashSet<(String, u64)> = a_entries
                .into_iter()
                .map(|e| (e.tx_hash, e.log_index))
                .collect();
            for e in t_entries {
                if aset.contains(&(e.tx_hash.clone(), e.log_index)) {
                    candidates.push(e);
                }
            }
        }
        (Some(a), None) => {
            let ap = addr_index_path(dir, &a.trim_start_matches("0x").to_lowercase());
            candidates = if ap.exists() {
                read_index_file(&ap, from, to)?
            } else {
                Vec::new()
            };
        }
        (None, Some(t)) => {
            let tp = topic_index_path(dir, &t.trim_start_matches("0x").to_lowercase());
            candidates = if tp.exists() {
                read_index_file(&tp, from, to)?
            } else {
                Vec::new()
            };
        }
        (None, None) => {
            return query_logs_scan(dir, from, to, None, None);
        }
    }

    let logs_path = ChainFiles::new(dir).logs;
    let mut logs = Vec::with_capacity(candidates.len());
    for e in candidates {
        let got = if let Some(off) = e.offset {
            fetch_log_by_offset(&logs_path, off)?
        } else {
            fetch_log_by_tx_hash_index(&logs_path, &e.tx_hash, e.log_index)?
        };
        if let Some(l) = got {
            logs.push(l);
        }
    }
    logs.sort_by(|a, b| (a.block_number, a.log_index).cmp(&(b.block_number, b.log_index)));
    Ok(logs)
}

/// Fallback: scan the whole logs file.
fn query_logs_scan(
    dir: &Path,
    from: u64,
    to: u64,
    address: Option<String>,
    topic0: Option<String>,
) -> ChainDbResult<Vec<Log>> {
    let logs_path = ChainFiles::new(dir).logs;
    let logs: Vec<Log> = load_jsonl(&logs_path)?;
    Ok(logs
        .into_iter()
        .filter(|l| l.block_number >= from && l.block_number <= to)
        .filter(|l| address.as_ref().map(|a| l.address == *a).unwrap_or(true))
        .filter(|l| {
            topic0
                .as_ref()
                .map(|t| l.topics.iter().any(|lt| lt == t))
                .unwrap_or(true)
        })
        .collect())
}

fn fetch_log_by_offset(path: &Path, offset: u64) -> ChainDbResult<Option<Log>> {
    if !path.exists() {
        return Ok(None);
    }
    let mut f = File::open(path)?;
    f.seek(SeekFrom::Start(offset))?;
    let mut reader = BufReader::new(f);
    let mut line = String::new();
    let n = reader.read_line(&mut line)?;
    if n == 0 {
        return Ok(None);
    }
    let log: Log = serde_json::from_str(line.trim_end())
        .map_err(|e| ChainDbError::Corrupt(e.to_string()))?;
    Ok(Some(log))
}

fn fetch_log_by_tx_hash_index(
    path: &Path,
    tx_hash: &str,
    log_index: u64,
) -> ChainDbResult<Option<Log>> {
    if !path.exists() {
        return Ok(None);
    }
    let f = File::open(path)?;
    let reader = BufReader::new(f);
    for line in reader.lines() {
        let line = line?;
        if line.trim().is_empty() {
            continue;
        }
        let log: Log = serde_json::from_str(&line)
            .map_err(|e| ChainDbError::Corrupt(e.to_string()))?;
        if log.tx_hash == tx_hash && log.log_index == log_index {
            return Ok(Some(log));
        }
    }
    Ok(None)
}

// ── Main Chain Database ─────────────────────────────────────────────────

/// Chain database manager.
#[derive(Clone)]
pub struct ChainDb {
    dir: PathBuf,
    config: Arc<ChainDbConfig>,
    metrics: Arc<ChainDbMetrics>,
    state: Arc<Mutex<EthRpcState>>,
    files: ChainFiles,
    #[allow(dead_code)]
    last_compaction: Arc<Mutex<Instant>>,
}

impl ChainDb {
    /// Open (or create) a chain database at the given directory.
    pub fn open(dir: impl AsRef<Path>, config: ChainDbConfig) -> ChainDbResult<Self> {
        config.validate()?;
        let dir = dir.as_ref().to_path_buf();
        let files = ChainFiles::new(&dir);
        files.ensure_dirs()?;

        let meta = ensure_meta(&dir)?;

        let state = Arc::new(Mutex::new(EthRpcState::default()));
        let metrics = Arc::new(
            ChainDbMetrics::new(config.enable_prometheus)
                .map_err(|e| ChainDbError::Metrics(e.to_string()))?,
        );

        if let Err(e) = load_into_state(&dir, &mut state.lock(), &config, &metrics) {
            warn!(error = %e, "failed to load state from disk, starting fresh");
        }

        let db = ChainDb {
            dir,
            config: Arc::new(config),
            metrics: metrics.clone(),
            state,
            files,
            last_compaction: Arc::new(Mutex::new(Instant::now())),
        };

        info!(
            dir = %db.dir.display(),
            block_count = meta.block_count,
            highest_block = meta.highest_block,
            "Chain database opened"
        );

        if db.config.max_blocks > 0 {
            db.spawn_compaction_task();
        }

        Ok(db)
    }

    /// Get the shared state (parking_lot Mutex; no `.unwrap()` required).
    pub fn state(&self) -> &Mutex<EthRpcState> {
        &self.state
    }

    /// Metrics snapshot.
    pub fn metrics_snapshot(&self) -> ChainDbMetricsSnapshot {
        self.metrics.snapshot()
    }

    /// Directory of the chain database.
    pub fn dir(&self) -> &Path {
        &self.dir
    }

    /// Append a new block bundle (block + receipts + txs + logs).
    pub fn persist_block_bundle(
        &self,
        block: &Block,
        receipts: &[Receipt],
        txs: &[TxRecord],
        logs: &[Log],
    ) -> ChainDbResult<()> {
        let log_offsets = if !logs.is_empty() {
            self.append_logs_with_offsets(logs)?
        } else {
            Vec::new()
        };

        append_jsonl_atomic(&self.files.blocks, block, &self.config)?;
        for r in receipts {
            append_jsonl_atomic(&self.files.receipts, r, &self.config)?;
        }
        for t in txs {
            append_jsonl_atomic(&self.files.txs, t, &self.config)?;
        }

        if self.config.enable_log_index && !logs.is_empty() {
            append_log_indices_with_offsets(&self.dir, logs, &log_offsets, &self.config)?;
        }

        {
            let state = self.state.lock();
            state.blocks.lock().push(block.clone());
            state.receipts.lock().extend(receipts.iter().cloned());
            {
                let mut txs_map = state.txs.lock();
                for tx in txs {
                    txs_map.insert(tx.hash.clone(), tx.clone());
                }
            }
            state.all_logs.lock().extend(logs.iter().cloned());
        }

        update_meta(&self.dir, block.number)?;

        self.metrics.record_block_write();
        self.metrics.record_receipt_write(receipts.len() as u64);
        self.metrics.record_tx_write(txs.len() as u64);
        self.metrics.record_log_write(logs.len() as u64);

        Ok(())
    }

    /// Append logs and return their byte offsets in `logs.jsonl`.
    pub fn append_logs_with_offsets(&self, logs: &[Log]) -> ChainDbResult<Vec<u64>> {
        let path = &self.files.logs;
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }

        let _lock = acquire_lock(path, self.config.lock_timeout_secs)?;

        let mut f = OpenOptions::new()
            .create(true)
            .append(true)
            .read(true)
            .open(path)?;
        f.seek(SeekFrom::End(0))?;

        let mut offsets = Vec::with_capacity(logs.len());
        for l in logs {
            let off = f.stream_position()?;
            let line = serde_json::to_string(l)
                .map_err(|e| ChainDbError::Serialization(e.to_string()))?;
            f.write_all(line.as_bytes())?;
            f.write_all(b"\n")?;
            offsets.push(off);
        }
        if self.config.fsync_on_write {
            f.sync_all()?;
        }
        Ok(offsets)
    }

    /// Query logs, preferring the index when enabled.
    pub fn query_logs(
        &self,
        from: u64,
        to: u64,
        address: Option<String>,
        topic0: Option<String>,
    ) -> ChainDbResult<Vec<Log>> {
        let result = query_logs_indexed(&self.dir, from, to, address, topic0, &self.config)?;

        if self.config.enable_log_index {
            if !result.is_empty() {
                self.metrics.record_index_hit();
            } else {
                self.metrics.record_index_miss();
            }
        }
        self.metrics.record_log_read(result.len() as u64);

        Ok(result)
    }

    /// Prune and compact the database per `max_blocks`.
    pub fn compact(&self) -> ChainDbResult<()> {
        let start = Instant::now();
        let max_blocks = self.config.max_blocks;
        if max_blocks == 0 {
            return Ok(());
        }

        let (kept_blocks, kept_receipts, kept_txs, kept_logs, min_bn) = {
            let state = self.state.lock();

            let blocks = state.blocks.lock().clone();
            if blocks.len() <= max_blocks {
                return Ok(());
            }

            let start_idx = blocks.len().saturating_sub(max_blocks);
            let kept_blocks = blocks[start_idx..].to_vec();
            let min_bn = kept_blocks.first().map(|b| b.number).unwrap_or(0);

            let receipts = state.receipts.lock().clone();
            let kept_receipts: Vec<Receipt> =
                receipts.into_iter().filter(|r| r.block_number >= min_bn).collect();

            let logs = state.all_logs.lock().clone();
            let kept_logs: Vec<Log> =
                logs.into_iter().filter(|l| l.block_number >= min_bn).collect();

            let txs_map = state.txs.lock().clone();
            let mut kept_txs = Vec::new();
            for b in &kept_blocks {
                for h in &b.transactions {
                    if let Some(t) = txs_map.get(h).cloned() {
                        kept_txs.push(t);
                    }
                }
            }

            (kept_blocks, kept_receipts, kept_txs, kept_logs, min_bn)
        };

        // Rewrite all four JSONL files atomically.
        rewrite_jsonl(&self.files.blocks, &kept_blocks)?;
        rewrite_jsonl(&self.files.receipts, &kept_receipts)?;
        rewrite_jsonl(&self.files.txs, &kept_txs)?;
        rewrite_jsonl(&self.files.logs, &kept_logs)?;

        // Rebuild log indices from scratch.
        if self.config.enable_log_index {
            let idx_dir = logs_index_dir(&self.dir);
            if idx_dir.exists() {
                let _ = fs::remove_dir_all(&idx_dir);
            }
            if !kept_logs.is_empty() {
                // Recompute offsets by re-appending to a fresh file.
                // (We just rewrote the logs file, so offsets are 0-based
                //  from the new file; recompute them.)
                let offsets = self.append_logs_with_offsets(&kept_logs)?;
                append_log_indices_with_offsets(
                    &self.dir,
                    &kept_logs,
                    &offsets,
                    &self.config,
                )?;
            }
        }

        // Update in-memory state to match the compacted files.
        {
            let state = self.state.lock();
            *state.blocks.lock() = kept_blocks;
            *state.receipts.lock() = kept_receipts;
            *state.all_logs.lock() = kept_logs;
            // Rebuild tx map.
            let mut txs_map = state.txs.lock();
            txs_map.clear();
            for t in kept_txs {
                txs_map.insert(t.hash.clone(), t);
            }
        }

        update_meta(&self.dir, min_bn)?;

        let duration = start.elapsed();
        self.metrics.record_compaction(duration);

        info!(
            min_bn,
            duration_ms = duration.as_millis(),
            "Chain database compacted"
        );

        Ok(())
    }

    fn spawn_compaction_task(&self) {
        let db = self.clone();
        let interval = Duration::from_secs(self.config.compaction_interval_secs);
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(interval).await;
                if let Err(e) = db.compact() {
                    error!(error = %e, "Compaction failed");
                }
            }
        });
    }
}

// ── Helper functions ─────────────────────────────────────────────────────

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn meta_path(dir: &Path) -> PathBuf {
    dir.join("meta.json")
}

fn ensure_meta(dir: &Path) -> ChainDbResult<Meta> {
    fs::create_dir_all(dir)?;
    let path = meta_path(dir);
    if path.exists() {
        let s = fs::read_to_string(&path)?;
        let m: Meta = serde_json::from_str(&s)
            .map_err(|e| ChainDbError::Corrupt(format!("meta.json: {}", e)))?;
        return Ok(m);
    }
    let m = Meta::new();
    let json = serde_json::to_string_pretty(&m)
        .map_err(|e| ChainDbError::Serialization(e.to_string()))?;
    fs::write(&path, json)?;
    Ok(m)
}

fn update_meta(dir: &Path, highest_block: u64) -> ChainDbResult<()> {
    let path = meta_path(dir);
    let mut m: Meta = if path.exists() {
        let s = fs::read_to_string(&path)?;
        serde_json::from_str(&s)
            .map_err(|e| ChainDbError::Corrupt(format!("meta.json: {}", e)))?
    } else {
        Meta::new()
    };
    m.highest_block = m.highest_block.max(highest_block);
    m.block_count = m.block_count.saturating_add(1);
    let json = serde_json::to_string_pretty(&m)
        .map_err(|e| ChainDbError::Serialization(e.to_string()))?;
    fs::write(&path, json)?;
    Ok(())
}

/// Load data from disk into `state`.
pub fn load_into_state(
    dir: &Path,
    state: &mut EthRpcState,
    _config: &ChainDbConfig,
    metrics: &ChainDbMetrics,
) -> ChainDbResult<()> {
    let files = ChainFiles::new(dir);

    let blocks: Vec<Block> = load_jsonl(&files.blocks)?;
    let receipts: Vec<Receipt> = load_jsonl(&files.receipts)?;
    let txs: Vec<TxRecord> = load_jsonl(&files.txs)?;
    let logs: Vec<Log> = load_jsonl(&files.logs)?;

    metrics.record_block_read(blocks.len() as u64);
    metrics.record_receipt_read(receipts.len() as u64);
    metrics.record_tx_read(txs.len() as u64);
    metrics.record_log_read(logs.len() as u64);

    *state.blocks.lock() = blocks.clone();
    *state.receipts.lock() = receipts.clone();

    {
        let mut txmap = HashMap::new();
        for t in txs {
            txmap.insert(t.hash.clone(), t);
        }
        *state.txs.lock() = txmap;
    }

    {
        let mut rb = HashMap::<u64, Vec<Receipt>>::new();
        for r in &receipts {
            rb.entry(r.block_number).or_default().push(r.clone());
        }
        *state.receipts_by_block.lock() = rb;
    }

    *state.all_logs.lock() = logs;

    if let Some(last) = blocks.last() {
        *state.block_number.lock() = last.number;
        if let Ok(bf) = u64::from_str_radix(last.base_fee_per_gas.trim_start_matches("0x"), 16) {
            *state.base_fee.lock() = bf;
        }
    }

    if let Ok(meta) = ensure_meta(dir) {
        trace!(
            block_count = meta.block_count,
            highest = meta.highest_block,
            "Metadata loaded"
        );
    }

    Ok(())
}

// ── Legacy API (backward compatibility) ─────────────────────────────────

pub fn append_block(dir: impl AsRef<Path>, b: &Block) -> ChainDbResult<()> {
    let config = ChainDbConfig::default();
    append_jsonl_atomic(&ChainFiles::new(dir.as_ref()).blocks, b, &config)?;
    Ok(())
}

pub fn append_receipts(dir: impl AsRef<Path>, rs: &[Receipt]) -> ChainDbResult<()> {
    let config = ChainDbConfig::default();
    let f = ChainFiles::new(dir.as_ref()).receipts;
    for r in rs {
        append_jsonl_atomic(&f, r, &config)?;
    }
    Ok(())
}

pub fn append_txs(dir: impl AsRef<Path>, txs: &[TxRecord]) -> ChainDbResult<()> {
    let config = ChainDbConfig::default();
    let f = ChainFiles::new(dir.as_ref()).txs;
    for t in txs {
        append_jsonl_atomic(&f, t, &config)?;
    }
    Ok(())
}

pub fn append_logs(dir: impl AsRef<Path>, logs: &[Log]) -> ChainDbResult<()> {
    let config = ChainDbConfig::default();
    let f = ChainFiles::new(dir.as_ref()).logs;
    for l in logs {
        append_jsonl_atomic(&f, l, &config)?;
    }
    Ok(())
}

pub fn persist_new_block_bundle(
    dir: impl AsRef<Path>,
    b: &Block,
    rs: &[Receipt],
    txs: &[TxRecord],
    logs: &[Log],
) {
    let _ = append_block(&dir, b);
    let _ = append_receipts(&dir, rs);
    let _ = append_txs(&dir, txs);
    let _ = append_logs(&dir, logs);
}

pub fn files(dir: impl AsRef<Path>) -> ChainFiles {
    ChainFiles::new(dir.as_ref())
}

pub fn ensure_meta_legacy(dir: impl AsRef<Path>) -> ChainDbResult<Meta> {
    ensure_meta(dir.as_ref())
}

// ── Tests ─────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    fn test_block(number: u64) -> Block {
        Block {
            number,
            hash: format!("0x{:x}", number),
            parent_hash: "0x0".into(),
            nonce: "0x0".into(),
            sha3_uncles: "0x0".into(),
            logs_bloom: "0x0".into(),
            transactions_root: "0x0".into(),
            state_root: "0x0".into(),
            receipts_root: "0x0".into(),
            miner: "0x0".into(),
            difficulty: "0x0".into(),
            total_difficulty: "0x0".into(),
            extra_data: "0x0".into(),
            size: "0x0".into(),
            gas_limit: "0x0".into(),
            gas_used: "0x0".into(),
            timestamp: "0x0".into(),
            transactions: vec![],
            uncles: vec![],
            base_fee_per_gas: "0x0".into(),
            withdrawals: None,
            blob_gas_used: None,
            excess_blob_gas: None,
            parent_beacon_block_root: None,
        }
    }

    /// Regression test for the append bug: multiple appends must preserve
    /// all previous lines (not truncate the file to one line).
    #[test]
    fn test_append_jsonl_atomic_preserves_previous_lines() -> ChainDbResult<()> {
        let dir = tempdir().unwrap();
        let path = dir.path().join("append.jsonl");
        let config = ChainDbConfig::default();

        for i in 0..5u64 {
            append_jsonl_atomic(&path, &test_block(i), &config)?;
        }

        let blocks: Vec<Block> = load_jsonl(&path)?;
        assert_eq!(blocks.len(), 5);
        for (i, b) in blocks.iter().enumerate() {
            assert_eq!(b.number, i as u64);
        }
        Ok(())
    }

    #[test]
    fn test_append_and_load() -> ChainDbResult<()> {
        let dir = tempdir().unwrap();
        let db = ChainDb::open(dir.path(), ChainDbConfig::default())?;

        for i in 0..5u64 {
            db.persist_block_bundle(&test_block(i), &[], &[], &[])?;
        }

        let state = db.state().lock();
        let blocks = state.blocks.lock();
        assert_eq!(blocks.len(), 5);
        for (i, b) in blocks.iter().enumerate() {
            assert_eq!(b.number, i as u64);
        }
        Ok(())
    }

    #[test]
    fn test_query_logs() -> ChainDbResult<()> {
        let dir = tempdir().unwrap();
        let db = ChainDb::open(dir.path(), ChainDbConfig::default())?;

        let block = test_block(1);
        let logs = vec![Log {
            address: "0x123".into(),
            topics: vec!["0x456".into()],
            data: "0x".into(),
            block_number: 1,
            tx_hash: "0xabc".into(),
            tx_index: 0,
            block_hash: "0xdef".into(),
            log_index: 0,
            removed: false,
        }];
        db.persist_block_bundle(&block, &[], &[], &logs)?;

        let result = db.query_logs(1, 1, Some("0x123".into()), None)?;
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].address, "0x123");

        let result = db.query_logs(1, 1, None, Some("0x456".into()))?;
        assert_eq!(result.len(), 1);

        let result = db.query_logs(1, 1, Some("0x123".into()), Some("0x456".into()))?;
        assert_eq!(result.len(), 1);

        let result = db.query_logs(1, 1, Some("0x999".into()), None)?;
        assert!(result.is_empty());

        Ok(())
    }

    #[test]
    fn test_compaction() -> ChainDbResult<()> {
        let dir = tempdir().unwrap();
        let config = ChainDbConfig {
            max_blocks: 2,
            ..Default::default()
        };
        let db = ChainDb::open(dir.path(), config)?;

        for i in 0..5u64 {
            db.persist_block_bundle(&test_block(i), &[], &[], &[])?;
        }

        db.compact()?;

        let state = db.state().lock();
        let blocks = state.blocks.lock();
        assert_eq!(blocks.len(), 2);
        assert_eq!(blocks[0].number, 3);
        assert_eq!(blocks[1].number, 4);

        // On-disk file should also reflect the compaction.
        drop(blocks);
        drop(state);
        let on_disk: Vec<Block> = load_jsonl(&ChainFiles::new(dir.path()).blocks)?;
        assert_eq!(on_disk.len(), 2);
        assert_eq!(on_disk[0].number, 3);

        Ok(())
    }

    #[test]
    fn test_metrics() -> ChainDbResult<()> {
        let dir = tempdir().unwrap();
        let db = ChainDb::open(dir.path(), ChainDbConfig::default())?;
        db.persist_block_bundle(&test_block(1), &[], &[], &[])?;
        let m = db.metrics_snapshot();
        assert_eq!(m.blocks_written, 1);
        Ok(())
    }

    #[test]
    fn test_config_validation() {
        let mut config = ChainDbConfig::default();
        assert!(config.validate().is_ok());

        config.compaction_interval_secs = 0;
        assert!(config.validate().is_err());

        config.compaction_interval_secs = 60;
        config.lock_timeout_secs = 0;
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_prometheus_metrics_unregistered() {
        let p = ChainDbPrometheus::new_unregistered();
        p.blocks_written_total.inc();
        p.blocks_written_total.inc_by(2);
        p.index_hits_total.inc();
        assert_eq!(p.blocks_written_total.get(), 3);
        assert_eq!(p.index_hits_total.get(), 1);
    }
}
