use std::fs::{self, OpenOptions};
use std::collections::HashSet;
use std::io::{self, BufRead, BufReader, Write};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::rpc::eth_rpc::{Block, Log, Receipt, TxRecord, EthRpcState};

pub const SCHEMA_VERSION: u32 = 1;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Meta {
    pub schema_version: u32,
    pub created_at_unix: u64,
}


#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChainFiles {
    pub blocks: PathBuf,
    pub receipts: PathBuf,
    pub txs: PathBuf,
    pub logs: PathBuf,
}

fn meta_path(dir: &Path) -> PathBuf { dir.join("meta.json") }

pub fn files(dir: impl AsRef<Path>) -> ChainFiles {
    let d = dir.as_ref();
    ChainFiles {
        blocks: d.join("blocks.jsonl"),
        receipts: d.join("receipts.jsonl"),
        txs: d.join("txs.jsonl"),
        logs: d.join("logs.jsonl"),
    }
}

fn append_jsonl<T: Serialize>(path: &Path, value: &T) -> io::Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let mut f = OpenOptions::new().create(true).append(true).open(path)?;
    let line = serde_json::to_string(value)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;
    f.write_all(line.as_bytes())?;
    f.write_all(b"\n")?;
    Ok(())
}

pub fn append_block(dir: impl AsRef<Path>, b: &Block) -> io::Result<()> {
    append_jsonl(&files(dir).blocks, b)
}

pub fn append_receipts(dir: impl AsRef<Path>, rs: &[Receipt]) -> io::Result<()> {
    let f = files(dir).receipts;
    for r in rs {
        append_jsonl(&f, r)?;
    }
    Ok(())
}

pub fn append_txs(dir: impl AsRef<Path>, txs: &[TxRecord]) -> io::Result<()> {
    let f = files(dir).txs;
    for t in txs {
        append_jsonl(&f, t)?;
    }
    Ok(())
}

pub fn append_logs(dir: impl AsRef<Path>, logs: &[Log]) -> io::Result<()> {
    let f = files(dir).logs;
    for l in logs {
        append_jsonl(&f, l)?;
    }
    Ok(())
}

pub fn load_jsonl<T: for<'de> Deserialize<'de>>(path: &Path) -> io::Result<Vec<T>> {

    if !path.exists() {
        return Ok(vec![]);
    }
    let f = fs::File::open(path)?;
    let br = BufReader::new(f);
    let mut out = vec![];
    for line in br.lines() {
        let line = line?;
        if line.trim().is_empty() { continue; }
        let v: T = serde_json::from_str(&line)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;
        out.push(v);
    }
    Ok(out)
}

/// Rebuild in-memory indices from append-only files.
/// This is a "good enough" chain DB scaffold (append-only, crash-tolerant for partial lines).
pub fn load_into_state(dir: impl AsRef<Path>, st: &mut EthRpcState) -> io::Result<()> {
    let f = files(dir);

    let blocks: Vec<Block> = load_jsonl(&f.blocks)?;
    let receipts: Vec<Receipt> = load_jsonl(&f.receipts)?;
    let txs: Vec<TxRecord> = load_jsonl(&f.txs)?;
    let logs: Vec<Log> = load_jsonl(&f.logs)?;

    // Apply
    *st.blocks.lock().unwrap() = blocks.clone();
    *st.receipts.lock().unwrap() = receipts.clone();

    // tx map
    let mut txmap = std::collections::HashMap::new();
    for t in txs {
        txmap.insert(t.hash.clone(), t);
    }
    *st.txs.lock().unwrap() = txmap;

    // receipts_by_block
    let mut rb = std::collections::HashMap::<u64, Vec<Receipt>>::new();
    for r in receipts {
        rb.entry(r.block_number).or_default().push(r);
    }
    *st.receipts_by_block.lock().unwrap() = rb;

    // logs + indices
    *st.all_logs.lock().unwrap() = logs;

    // block_number + base_fee best-effort
    if let Some(last) = blocks.last() {
        *st.block_number.lock().unwrap() = last.number;
        if let Ok(bf) = u64::from_str_radix(last.base_fee_per_gas.trim_start_matches("0x"), 16) {
            *st.base_fee.lock().unwrap() = bf;
        }
    }

    Ok(())
}

pub fn persist_new_block_bundle(dir: impl AsRef<Path>, b: &Block, rs: &[Receipt], txs: &[TxRecord], logs: &[Log]) {
    let dir = dir.as_ref();
    let _ = append_block(dir, b);
    let _ = append_receipts(dir, rs);
    let _ = append_txs(dir, txs);
    let _ = append_logs(dir, logs);
}


fn now_unix() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs()
}

pub fn ensure_meta(dir: impl AsRef<Path>) -> io::Result<Meta> {
    let dir = dir.as_ref();
    fs::create_dir_all(dir)?;
    let p = meta_path(dir);
    if p.exists() {
        let s = fs::read_to_string(&p)?;
        let m: Meta = serde_json::from_str(&s)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;
        return Ok(m);
    }
    let m = Meta { schema_version: SCHEMA_VERSION, created_at_unix: now_unix() };
    fs::write(&p, serde_json::to_string_pretty(&m).unwrap())?;
    Ok(m)
}

fn logs_index_dir(dir: &Path) -> PathBuf { dir.join("log_index") }
fn addr_index_path(dir: &Path, addr_hex: &str) -> PathBuf { logs_index_dir(dir).join("by_address").join(format!("{addr_hex}.jsonl")) }
fn topic_index_path(dir: &Path, topic_hex: &str) -> PathBuf { logs_index_dir(dir).join("by_topic").join(format!("{topic_hex}.jsonl")) }

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogIndexEntry {
    pub block_number: u64,
    pub tx_hash: String,
    pub log_index: u64,
    /// Byte offset in logs.jsonl (v24+). If missing, fallback scan.
    pub offset: Option<u64>,
}

/// Append log index entries for fast eth_getLogs filtering by address/topic.
pub fn append_log_indices(dir: impl AsRef<Path>, logs: &[Log]) -> io::Result<()> {
    let dir = dir.as_ref();
    ensure_meta(dir)?;
    for l in logs {
        let entry = LogIndexEntry { block_number: l.block_number, tx_hash: l.tx_hash.clone(), log_index: l.log_index, offset: None };
        // by address
        let addr = l.address.trim_start_matches("0x").to_lowercase();
        append_jsonl(&addr_index_path(dir, &addr), &entry)?;
        // by each topic
        for t in l.topics.iter() {
            let th = t.trim_start_matches("0x").to_lowercase();
            append_jsonl(&topic_index_path(dir, &th), &entry)?;
        }
    }
    Ok(())
}

/// Compact a JSONL file by rewriting a full vector.
fn rewrite_jsonl<T: Serialize>(path: &Path, items: &[T]) -> io::Result<()> {
    if let Some(parent) = path.parent() { fs::create_dir_all(parent)?; }
    let mut f = OpenOptions::new().create(true).write(true).truncate(true).open(path)?;
    for it in items {
        let line = serde_json::to_string(it).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;
        f.write_all(line.as_bytes())?;
        f.write_all(b"\n")?;
    }
    Ok(())
}

/// Prune and compact chain DB to keep only the last `keep_blocks` blocks.
/// Also rebuilds `logs.jsonl` and indices.
pub fn prune_and_compact(dir: impl AsRef<Path>, st: &EthRpcState, keep_blocks: usize) -> io::Result<()> {
    let dir = dir.as_ref();
    ensure_meta(dir)?;
    let f = files(dir);

    let blocks = st.blocks.lock().unwrap().clone();
    let receipts = st.receipts.lock().unwrap().clone();
    let txs_map = st.txs.lock().unwrap().clone();
    let logs = st.all_logs.lock().unwrap().clone();

    let start = blocks.len().saturating_sub(keep_blocks);
    let kept_blocks = blocks[start..].to_vec();
    let min_bn = kept_blocks.first().map(|b| b.number).unwrap_or(0);

    let kept_receipts: Vec<Receipt> = receipts.into_iter().filter(|r| r.block_number >= min_bn).collect();
    let kept_logs: Vec<Log> = logs.into_iter().filter(|l| l.block_number >= min_bn).collect();

    // txs referenced by kept blocks
    let mut kept_txs: Vec<TxRecord> = vec![];
    for b in kept_blocks.iter() {
        for h in b.transactions.iter() {
            if let Some(t) = txs_map.get(h).cloned() { kept_txs.push(t); }
        }
    }

    rewrite_jsonl(&f.blocks, &kept_blocks)?;
    rewrite_jsonl(&f.receipts, &kept_receipts)?;
    rewrite_jsonl(&f.txs, &kept_txs)?;
    rewrite_jsonl(&f.logs, &kept_logs)?;

    // rebuild indices
    let idx = logs_index_dir(dir);
    if idx.exists() { let _ = fs::remove_dir_all(&idx); }
    {
        // rebuild logs file with fresh offsets
        let log_path = files(dir).logs;
        rewrite_jsonl(&log_path, &kept_logs)?;
        let offs = {
            // compute offsets by scanning file once
            use std::io::BufRead;
            let f = fs::File::open(&log_path)?;
            let mut br = BufReader::new(f);
            let mut offsets = vec![];
            let mut pos: u64 = 0;
            let mut line = String::new();
            loop {
                line.clear();
                let n = br.read_line(&mut line)?;
                if n == 0 { break; }
                offsets.push(pos);
                pos += n as u64;
            }
            offsets
        };
        append_log_indices_with_offsets(dir, &kept_logs, &offs)?;
    }

    Ok(())
}


/// Read index entries from a jsonl file, filter by block range.
fn read_index_file(path: &Path, from: u64, to: u64) -> io::Result<Vec<LogIndexEntry>> {
    let entries: Vec<LogIndexEntry> = load_jsonl(path).unwrap_or_default();
    Ok(entries.into_iter().filter(|e| e.block_number >= from && e.block_number <= to).collect())
}

/// Fetch a concrete Log from logs.jsonl by matching tx_hash + log_index.
/// This scans logs.jsonl; acceptable for scaffold. A production DB would store offsets.
fn fetch_log(dir: &Path, tx_hash: &str, log_index: u64) -> io::Result<Option<Log>> {
    let f = files(dir).logs;
    if !f.exists() { return Ok(None); }
    let items: Vec<Log> = load_jsonl(&f).unwrap_or_default();
    Ok(items.into_iter().find(|l| l.tx_hash == tx_hash && l.log_index == log_index))
}

/// Minimal indexed eth_getLogs:
/// - address: optional single address
/// - topics: optional first topic (single)
/// Falls back to scanning logs.jsonl if index file missing.
pub fn query_logs_indexed(dir: impl AsRef<Path>, from: u64, to: u64, address: Option<String>, topic0: Option<String>) -> io::Result<Vec<Log>> {
    let dir = dir.as_ref();
    ensure_meta(dir)?;

    let mut candidates: Vec<LogIndexEntry> = vec![];

    match (address.clone(), topic0.clone()) {
        (Some(a), Some(t)) => {
            let ap = addr_index_path(dir, a.trim_start_matches("0x"));
            let tp = topic_index_path(dir, t.trim_start_matches("0x"));
            let a_entries = if ap.exists() { read_index_file(&ap, from, to)? } else { vec![] };
            let t_entries = if tp.exists() { read_index_file(&tp, from, to)? } else { vec![] };
            // intersect by (tx_hash, log_index)
            let aset = std::collections::HashSet::<(String,u64)>::from_iter(a_entries.into_iter().map(|e|(e.tx_hash, e.log_index)));
            let mut out = vec![];
            for e in t_entries {
                if aset.contains(&(e.tx_hash.clone(), e.log_index)) {
                    out.push(LogIndexEntry{ block_number: e.block_number, tx_hash: e.tx_hash, log_index: e.log_index });
                }
            }
            candidates = out;
        }
        (Some(a), None) => {
            let ap = addr_index_path(dir, a.trim_start_matches("0x"));
            candidates = if ap.exists() { read_index_file(&ap, from, to)? } else { vec![] };
        }
        (None, Some(t)) => {
            let tp = topic_index_path(dir, t.trim_start_matches("0x"));
            candidates = if tp.exists() { read_index_file(&tp, from, to)? } else { vec![] };
        }
        (None, None) => {
            // no filters: scan logs file within range
            let f = files(dir).logs;
            let items: Vec<Log> = load_jsonl(&f).unwrap_or_default();
            return Ok(items.into_iter().filter(|l| l.block_number>=from && l.block_number<=to).collect());
        }
    }

    // fetch concrete logs
    let mut logs: Vec<Log> = vec![];
    for e in candidates {
        let got = if let Some(off) = e.offset {
            fetch_log_by_offset(dir, off)?
        } else {
            fetch_log(dir, &e.tx_hash, e.log_index)?
        };
        if let Some(l) = got { logs.push(l); }
    }
    // ensure stable ordering by block_number then log_index
    logs.sort_by(|a,b| (a.block_number, a.log_index).cmp(&(b.block_number,b.log_index)));
    Ok(logs)
}


/// Append logs to logs.jsonl and return byte offsets for each appended line.
/// Opens the file once and appends sequentially.
pub fn append_logs_record_offsets(dir: impl AsRef<Path>, logs: &[Log]) -> io::Result<Vec<u64>> {
    let dir = dir.as_ref();
    ensure_meta(dir)?;
    let path = files(dir).logs;
    if let Some(parent) = path.parent() { fs::create_dir_all(parent)?; }

    use std::io::{Seek, SeekFrom};
    let mut f = OpenOptions::new().create(true).append(true).read(true).open(&path)?;
    // Ensure we're at end
    f.seek(SeekFrom::End(0))?;

    let mut offsets = Vec::with_capacity(logs.len());
    for l in logs {
        let off = f.stream_position()?;
        let line = serde_json::to_string(l)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;
        f.write_all(line.as_bytes())?;
        f.write_all(b"\n")?;
        offsets.push(off);
    }
    Ok(offsets)
}

fn fetch_log_by_offset(dir: &Path, offset: u64) -> io::Result<Option<Log>> {
    use std::io::{Seek, SeekFrom};
    let path = files(dir).logs;
    if !path.exists() { return Ok(None); }
    let f = fs::File::open(&path)?;
    let mut br = BufReader::new(f);
    br.seek(SeekFrom::Start(offset))?;
    let mut line = String::new();
    let n = br.read_line(&mut line)?;
    if n == 0 { return Ok(None); }
    let l: Log = serde_json::from_str(line.trim_end())
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;
    Ok(Some(l))
}

/// Append log index entries with offsets (v24).
pub fn append_log_indices_with_offsets(dir: impl AsRef<Path>, logs: &[Log], offsets: &[u64]) -> io::Result<()> {
    let dir = dir.as_ref();
    ensure_meta(dir)?;
    if logs.len() != offsets.len() {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "logs/offsets mismatch"));
    }
    for (l, off) in logs.iter().zip(offsets.iter()) {
        let entry = LogIndexEntry { block_number: l.block_number, tx_hash: l.tx_hash.clone(), log_index: l.log_index, offset: Some(*off) };
        let addr = l.address.trim_start_matches("0x").to_lowercase();
        append_jsonl(&addr_index_path(dir, &addr), &entry)?;
        for t in l.topics.iter() {
            let th = t.trim_start_matches("0x").to_lowercase();
            append_jsonl(&topic_index_path(dir, &th), &entry)?;
        }
    }
    Ok(())
}
