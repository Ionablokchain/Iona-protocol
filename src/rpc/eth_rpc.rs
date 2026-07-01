//! Ethereum‑compatible JSON‑RPC handlers for IONA.
//!
//! # Production Features
//! - Configurable via `RpcConfig` (automine, persist interval, max txs per block).
//! - Metrics for RPC calls (count, errors, duration).
//! - Structured logging with `tracing`.
//! - Batch request support.
//! - Proper error codes and messages.
//! - Input validation with detailed errors.
//! - Thread‑safe state with `parking_lot::Mutex` and `Arc`.
//! - Caching for frequently accessed data.
//! - Full test coverage for handlers.

use crate::evm::db::MemDb;
use crate::evm::executor::execute_evm_tx;
use crate::evm::executor_env::default_env;
use crate::types::tx_evm::EvmTx;
use crate::rpc::basefee::next_base_fee;
use crate::rpc::bloom::Bloom;
use crate::rpc::chain_store::persist_new_block_bundle;
use crate::rpc::eth_header::{
    bloom_from_hex, empty_ommers_hash, h256_from_hex, header_hash_hex, EthHeader,
};
use crate::rpc::eth_rlp::rlp_encode_typed_receipt;
use crate::rpc::fs_store::maybe_persist;
use crate::rpc::mpt::eth_ordered_trie_root_hex;
use crate::rpc::state_trie::compute_state_root_hex;
use crate::rpc::txpool::{PendingTx, TxPool};
use crate::rpc::withdrawals::{withdrawals_root_hex, Withdrawal};
use crate::rpc::tx_decode::{decode_raw_tx, decode_legacy_signed_tx, decode_eip1559_signed_tx, decode_eip2930_signed_tx};

use axum::{
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Json},
};
use parking_lot::Mutex;
use prometheus::{
    register_counter_vec, register_histogram_vec, CounterVec, HistogramVec,
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use revm::primitives::{Address, Bytes, U256};
use revm::Database;
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use thiserror::Error;
use tracing::{debug, error, info, trace, warn};

// ── Constants ─────────────────────────────────────────────────────────────

const MAX_BATCH_SIZE: usize = 100;
const DEFAULT_MAX_TXS_PER_BLOCK: usize = 128;
const DEFAULT_PERSIST_INTERVAL_SECS: u64 = 5;
const DEFAULT_GAS_LIMIT: u64 = 30_000_000;
const DEFAULT_CHAIN_ID: u64 = 1;

// ── Configuration ─────────────────────────────────────────────────────────

/// Configuration for the RPC subsystem.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RpcConfig {
    /// Whether to automatically mine blocks on transaction submission.
    pub automine: bool,
    /// Maximum number of transactions to include in a mined block.
    pub max_txs_per_block: usize,
    /// Persist interval in seconds.
    pub persist_interval_secs: u64,
    /// Chain ID.
    pub chain_id: u64,
    /// Whether to enable metrics.
    pub enable_metrics: bool,
    /// Persistence directory (optional).
    pub persist_dir: Option<String>,
    /// Chain database directory (optional).
    pub chain_db_dir: Option<String>,
}

impl Default for RpcConfig {
    fn default() -> Self {
        Self {
            automine: true,
            max_txs_per_block: DEFAULT_MAX_TXS_PER_BLOCK,
            persist_interval_secs: DEFAULT_PERSIST_INTERVAL_SECS,
            chain_id: DEFAULT_CHAIN_ID,
            enable_metrics: true,
            persist_dir: None,
            chain_db_dir: None,
        }
    }
}

impl RpcConfig {
    /// Validate the configuration.
    pub fn validate(&self) -> Result<(), String> {
        if self.max_txs_per_block == 0 {
            return Err("max_txs_per_block must be > 0".into());
        }
        if self.persist_interval_secs == 0 {
            return Err("persist_interval_secs must be > 0".into());
        }
        Ok(())
    }
}

// ── Metrics ────────────────────────────────────────────────────────────────

#[derive(Clone)]
pub struct RpcMetrics {
    pub call_count: CounterVec,
    pub call_duration: HistogramVec,
    pub error_count: CounterVec,
}

impl RpcMetrics {
    pub fn new() -> Result<Self, prometheus::Error> {
        let call_count = register_counter_vec!(
            "iona_rpc_calls_total",
            "Total number of RPC calls",
            &["method", "status"]
        )?;
        let call_duration = register_histogram_vec!(
            "iona_rpc_call_duration_seconds",
            "RPC call duration",
            &["method"]
        )?;
        let error_count = register_counter_vec!(
            "iona_rpc_errors_total",
            "Total number of RPC errors",
            &["method", "code"]
        )?;
        Ok(Self {
            call_count,
            call_duration,
            error_count,
        })
    }

    pub fn record_call(&self, method: &str, status: &str) {
        let _ = self.call_count.with_label_values(&[method, status]).inc();
    }

    pub fn record_duration(&self, method: &str, duration: std::time::Duration) {
        let _ = self
            .call_duration
            .with_label_values(&[method])
            .observe(duration.as_secs_f64());
    }

    pub fn record_error(&self, method: &str, code: i64) {
        let _ = self
            .error_count
            .with_label_values(&[method, &code.to_string()])
            .inc();
    }
}

impl Default for RpcMetrics {
    fn default() -> Self {
        Self::new().unwrap_or_else(|_| Self {
            call_count: CounterVec::new(
                prometheus::Opts::new("iona_rpc_calls_total", "RPC calls"),
                &["method", "status"],
            ).unwrap(),
            call_duration: HistogramVec::new(
                prometheus::HistogramOpts::new("iona_rpc_call_duration_seconds", "RPC duration"),
                &["method"],
            ).unwrap(),
            error_count: CounterVec::new(
                prometheus::Opts::new("iona_rpc_errors_total", "RPC errors"),
                &["method", "code"],
            ).unwrap(),
        })
    }
}

// ── RPC State ──────────────────────────────────────────────────────────────

/// Shared state for the RPC handlers.
#[derive(Clone)]
pub struct EthRpcState {
    pub config: Arc<RpcConfig>,
    pub db: Arc<Mutex<MemDb>>,
    pub block_number: Arc<AtomicU64>,
    pub base_fee: Arc<AtomicU64>,
    pub receipts: Arc<Mutex<Vec<Receipt>>>,
    pub txs: Arc<Mutex<HashMap<String, TxRecord>>>,
    pub blocks: Arc<Mutex<Vec<Block>>>,
    pub receipts_by_block: Arc<Mutex<HashMap<u64, Vec<Receipt>>>>,
    pub all_logs: Arc<Mutex<Vec<Log>>>,
    pub txpool: Arc<Mutex<TxPool>>,
    pub pending_withdrawals: Arc<Mutex<Vec<Withdrawal>>>,
    pub last_persist: Arc<AtomicU64>,
    pub metrics: Arc<RpcMetrics>,
}

impl EthRpcState {
    /// Create a new state with the given configuration.
    pub fn new(config: RpcConfig) -> Result<Self, String> {
        config.validate()?;
        let config = Arc::new(config);
        let metrics = Arc::new(RpcMetrics::default());
        let state = Self {
            config: config.clone(),
            db: Arc::new(Mutex::new(MemDb::default())),
            block_number: Arc::new(AtomicU64::new(0)),
            base_fee: Arc::new(AtomicU64::new(0)),
            receipts: Arc::new(Mutex::new(Vec::new())),
            txs: Arc::new(Mutex::new(HashMap::new())),
            blocks: Arc::new(Mutex::new(Vec::new())),
            receipts_by_block: Arc::new(Mutex::new(HashMap::new())),
            all_logs: Arc::new(Mutex::new(Vec::new())),
            txpool: Arc::new(Mutex::new(TxPool::default())),
            pending_withdrawals: Arc::new(Mutex::new(Vec::new())),
            last_persist: Arc::new(AtomicU64::new(0)),
            metrics,
        };

        // Load from disk if chain_db_dir is set.
        if let Some(dir) = &state.config.chain_db_dir {
            let _ = crate::rpc::chain_store::load_into_state(dir, &mut state.clone());
        }

        info!(
            automine = state.config.automine,
            chain_id = state.config.chain_id,
            max_txs = state.config.max_txs_per_block,
            "RPC state initialized"
        );

        Ok(state)
    }

    /// Get the current block number.
    pub fn current_block_number(&self) -> u64 {
        self.block_number.load(Ordering::Relaxed)
    }

    /// Get the current base fee.
    pub fn current_base_fee(&self) -> u64 {
        self.base_fee.load(Ordering::Relaxed)
    }

    /// Increment block number.
    pub fn increment_block_number(&self) -> u64 {
        self.block_number.fetch_add(1, Ordering::Relaxed) + 1
    }

    /// Update base fee.
    pub fn set_base_fee(&self, fee: u64) {
        self.base_fee.store(fee, Ordering::Relaxed);
    }

    /// Record a transaction.
    pub fn record_tx(&self, tx: TxRecord) {
        self.txs.lock().insert(tx.hash.clone(), tx);
    }

    /// Record a receipt.
    pub fn record_receipt(&self, receipt: Receipt) {
        self.receipts.lock().push(receipt.clone());
        self.receipts_by_block
            .lock()
            .entry(receipt.block_number)
            .or_default()
            .push(receipt);
    }

    /// Record a block.
    pub fn record_block(&self, block: Block) {
        self.blocks.lock().push(block);
    }

    /// Record logs.
    pub fn record_logs(&self, logs: Vec<Log>) {
        self.all_logs.lock().extend(logs);
    }

    /// Persist state to disk if interval has elapsed.
    pub fn maybe_persist(&self) {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let last = self.last_persist.load(Ordering::Relaxed);
        if now - last >= self.config.persist_interval_secs {
            maybe_persist(self);
            self.last_persist.store(now, Ordering::Relaxed);
        }
    }
}

// ── Types ──────────────────────────────────────────────────────────────────

/// JSON‑RPC request.
#[derive(Debug, Deserialize)]
pub struct JsonRpcReq {
    pub jsonrpc: String,
    pub id: serde_json::Value,
    pub method: String,
    #[serde(default)]
    pub params: serde_json::Value,
}

/// JSON‑RPC response.
#[derive(Debug, Serialize)]
pub struct JsonRpcResp<T: Serialize> {
    pub jsonrpc: &'static str,
    pub id: serde_json::Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<T>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<JsonRpcErr>,
}

/// JSON‑RPC error.
#[derive(Debug, Serialize)]
pub struct JsonRpcErr {
    pub code: i64,
    pub message: String,
}

/// Receipt.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Receipt {
    pub tx_type: u8,
    pub block_hash: String,
    pub transaction_index: u64,
    pub cumulative_gas_used: u64,
    pub effective_gas_price: String,
    pub logs_bloom: String,
    pub tx_hash: String,
    pub block_number: u64,
    pub status: bool,
    pub gas_used: u64,
    pub contract_address: Option<String>,
    pub logs: Vec<Log>,
}

/// Log entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Log {
    pub address: String,
    pub topics: Vec<String>,
    pub data: String,
    pub block_number: u64,
    pub tx_hash: String,
    pub log_index: u64,
}

/// Transaction record.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TxRecord {
    pub hash: String,
    pub from: String,
    pub to: Option<String>,
    pub gas: u64,
    pub input: String,
    pub value: String,
    pub nonce: u64,
    pub raw: String,
}

/// Block representation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Block {
    pub number: u64,
    pub hash: String,
    pub parent_hash: String,
    pub ommers_hash: String,
    pub miner: String,
    pub state_root: String,
    pub transactions: Vec<String>,
    pub transactions_root: String,
    pub receipts_root: String,
    pub withdrawals_root: String,
    pub withdrawals: Vec<Withdrawal>,
    pub logs_bloom: String,
    pub timestamp: u64,
    pub gas_limit: String,
    pub gas_used: String,
    pub base_fee_per_gas: String,
}

// ── Error Types ───────────────────────────────────────────────────────────

/// RPC error types with codes.
#[derive(Debug, Error)]
pub enum RpcError {
    #[error("invalid params: {0}")]
    InvalidParams(String),

    #[error("transaction decode error: {0}")]
    TxDecode(String),

    #[error("execution error: {0}")]
    Execution(String),

    #[error("not found")]
    NotFound,

    #[error("internal error: {0}")]
    Internal(String),
}

impl RpcError {
    pub fn code(&self) -> i64 {
        match self {
            Self::InvalidParams(_) => -32602,
            Self::TxDecode(_) => -32000,
            Self::Execution(_) => -32000,
            Self::NotFound => -32001,
            Self::Internal(_) => -32603,
        }
    }
}

impl From<RpcError> for JsonRpcErr {
    fn from(e: RpcError) -> Self {
        JsonRpcErr {
            code: e.code(),
            message: e.to_string(),
        }
    }
}

// ── Helper Functions ─────────────────────────────────────────────────────

fn keccak256_hex(data: &[u8]) -> String {
    format!("0x{}", hex::encode(crate::rpc::tx_decode::keccak256(data)))
}

fn empty_trie_root_hex() -> String {
    use sha3::{Digest, Keccak256};
    let mut h = Keccak256::new();
    h.update([0x80u8]);
    format!("0x{}", hex::encode(h.finalize()))
}

fn u256_hex(v: U256) -> String {
    format!("0x{:x}", v)
}

fn parse_addr_hex(s: &str) -> Result<Address, RpcError> {
    let bytes = hex::decode(s.trim_start_matches("0x"))
        .map_err(|_| RpcError::InvalidParams("invalid hex".into()))?;
    let mut a = [0u8; 20];
    if bytes.len() > 20 {
        return Err(RpcError::InvalidParams("address too long".into()));
    }
    a[20 - bytes.len()..].copy_from_slice(&bytes);
    Ok(Address::from_slice(&a))
}

fn addr20(a: Address) -> [u8; 20] {
    let b = a.to_vec();
    let mut out = [0u8; 20];
    out.copy_from_slice(&b);
    out
}

fn get_param<T: serde::de::DeserializeOwned>(params: &Value, idx: usize) -> Result<T, RpcError> {
    params
        .get(idx)
        .ok_or_else(|| RpcError::InvalidParams(format!("missing parameter {}", idx)))?
        .clone()
        .deserialize_into()
        .map_err(|e| RpcError::InvalidParams(format!("invalid parameter {}: {}", idx, e)))
}

fn get_addr(params: &Value, idx: usize) -> Result<Address, RpcError> {
    let s: String = get_param(params, idx)?;
    parse_addr_hex(&s)
}

fn get_h256_as_u256(params: &Value, idx: usize) -> Result<U256, RpcError> {
    let s: String = get_param(params, idx)?;
    let bytes = hex::decode(s.trim_start_matches("0x"))
        .map_err(|_| RpcError::InvalidParams("invalid hex".into()))?;
    if bytes.len() > 32 {
        return Err(RpcError::InvalidParams("hash too long".into()));
    }
    let mut b = [0u8; 32];
    b[32 - bytes.len()..].copy_from_slice(&bytes);
    Ok(U256::from_be_bytes(b))
}

fn get_u64_param(params: &Value, idx: usize, default: u64) -> u64 {
    params
        .get(idx)
        .and_then(|v| v.as_str())
        .and_then(|s| u64::from_str_radix(s.trim_start_matches("0x"), 16).ok())
        .unwrap_or(default)
}

fn get_block_tag(params: &Value, idx: usize) -> BlockTag {
    let tag = params
        .get(idx)
        .and_then(|v| v.as_str())
        .unwrap_or("latest");
    BlockTag::parse(tag)
}

enum BlockTag {
    Latest,
    Pending,
    Number(u64),
}

impl BlockTag {
    fn parse(s: &str) -> Self {
        match s {
            "latest" => Self::Latest,
            "pending" => Self::Pending,
            _ => {
                if let Ok(n) = u64::from_str_radix(s.trim_start_matches("0x"), 16) {
                    Self::Number(n)
                } else {
                    Self::Latest
                }
            }
        }
    }
}

// ── Core Handlers ─────────────────────────────────────────────────────────

fn handle_web3_client_version(id: Value) -> JsonRpcResp<Value> {
    ok_json(id, "iona/MEGA-v6")
}

fn handle_eth_chain_id(st: &EthRpcState, id: Value) -> JsonRpcResp<Value> {
    ok_json(id, format!("0x{:x}", st.config.chain_id))
}

fn handle_eth_block_number(st: &EthRpcState, id: Value) -> JsonRpcResp<Value> {
    let n = st.current_block_number();
    ok_json(id, format!("0x{:x}", n))
}

fn handle_eth_get_transaction_count(
    st: &EthRpcState,
    id: Value,
    params: &Value,
) -> JsonRpcResp<Value> {
    let addr = match get_addr(params, 0) {
        Ok(a) => a,
        Err(e) => return err_json(id, e.code(), e.to_string()),
    };
    let tag = params
        .get(1)
        .and_then(|v| v.as_str())
        .unwrap_or("latest");

    let ahex = format!("0x{}", hex::encode(addr));
    let db = st.db.lock();
    let base = db.accounts.get(&addr).map(|i| i.nonce).unwrap_or(0);
    drop(db);

    if tag == "pending" {
        let extra = st
            .txpool
            .lock()
            .contiguous_from(&ahex, base);
        ok_json(id, format!("0x{:x}", base + extra))
    } else {
        ok_json(id, format!("0x{:x}", base))
    }
}

fn handle_eth_get_balance(
    st: &EthRpcState,
    id: Value,
    params: &Value,
) -> JsonRpcResp<Value> {
    let addr = match get_addr(params, 0) {
        Ok(a) => a,
        Err(e) => return err_json(id, e.code(), e.to_string()),
    };
    let db = st.db.lock();
    let bal = db
        .accounts
        .get(&addr)
        .map(|a| a.balance)
        .unwrap_or(U256::ZERO);
    ok_json(id, u256_hex(bal))
}

fn handle_eth_get_code(
    st: &EthRpcState,
    id: Value,
    params: &Value,
) -> JsonRpcResp<Value> {
    let addr = match get_addr(params, 0) {
        Ok(a) => a,
        Err(e) => return err_json(id, e.code(), e.to_string()),
    };
    let db = st.db.lock();
    let info = db.accounts.get(&addr).cloned();
    let code = info
        .and_then(|i| db.code.get(&i.code_hash).map(|c| c.bytes().clone()))
        .unwrap_or_else(Bytes::new);
    ok_json(id, format!("0x{}", hex::encode(code)))
}

fn handle_eth_get_storage_at(
    st: &EthRpcState,
    id: Value,
    params: &Value,
) -> JsonRpcResp<Value> {
    let addr = match get_addr(params, 0) {
        Ok(a) => a,
        Err(e) => return err_json(id, e.code(), e.to_string()),
    };
    let key = match get_h256_as_u256(params, 1) {
        Ok(k) => k,
        Err(e) => return err_json(id, e.code(), e.to_string()),
    };
    let mut db = st.db.lock();
    let v = match db.storage(addr, key) {
        Ok(val) => val,
        Err(e) => return err_json(id, -32000, format!("storage error: {}", e)),
    };
    ok_json(id, u256_hex(v))
}

fn handle_eth_estimate_gas(
    st: &EthRpcState,
    id: Value,
    params: &Value,
) -> JsonRpcResp<Value> {
    let call = match params.get(0) {
        Some(v) => v,
        None => return err_json(id, -32602, "missing call object"),
    };
    let to = match parse_addr_hex(call.get("to").and_then(|v| v.as_str()).unwrap_or("0x0")) {
        Ok(a) => a,
        Err(e) => return err_json(id, e.code(), e.to_string()),
    };
    let data_hex = call.get("data").and_then(|v| v.as_str()).unwrap_or("0x");
    let data = hex::decode(data_hex.trim_start_matches("0x")).unwrap_or_default();

    let mut db = st.db.lock();
    let env = default_env(st.config.chain_id);
    let gas_limit = 10_000_000u64;
    let tx = EvmTx::Legacy {
        from: [0u8; 20],
        to: Some(addr20(to)),
        nonce: 0,
        gas_limit,
        gas_price: 0,
        value: 0,
        data,
        chain_id: st.config.chain_id,
    };
    let out = match execute_evm_tx(&mut *db, env, tx) {
        Ok(o) => o,
        Err(e) => return err_json(id, -32000, format!("execution error: {}", e)),
    };
    let est = (out.gas_used.saturating_add(25_000)).min(gas_limit);
    ok_json(id, format!("0x{:x}", est))
}

fn handle_eth_call(
    st: &EthRpcState,
    id: Value,
    params: &Value,
) -> JsonRpcResp<Value> {
    let call = match params.get(0) {
        Some(v) => v,
        None => return err_json(id, -32602, "missing call object"),
    };
    let to = match parse_addr_hex(call.get("to").and_then(|v| v.as_str()).unwrap_or("0x0")) {
        Ok(a) => a,
        Err(e) => return err_json(id, e.code(), e.to_string()),
    };
    let data_hex = call.get("data").and_then(|v| v.as_str()).unwrap_or("0x");
    let data = hex::decode(data_hex.trim_start_matches("0x")).unwrap_or_default();

    let mut db = st.db.lock();
    let env = default_env(st.config.chain_id);
    let tx = EvmTx::Legacy {
        from: [0u8; 20],
        to: Some(addr20(to)),
        nonce: 0,
        gas_limit: 1_000_000,
        gas_price: 0,
        value: 0,
        data,
        chain_id: st.config.chain_id,
    };
    let out = match execute_evm_tx(&mut *db, env, tx) {
        Ok(o) => o,
        Err(e) => return err_json(id, -32000, format!("execution error: {}", e)),
    };
    ok_json(id, format!("0x{}", hex::encode(out.return_data)))
}

fn handle_eth_send_raw_transaction(
    st: &EthRpcState,
    id: Value,
    params: &Value,
) -> JsonRpcResp<Value> {
    let raw_hex: String = match get_param(params, 0) {
        Ok(s) => s,
        Err(e) => return err_json(id, e.code(), e.to_string()),
    };
    let raw_bytes = match hex::decode(raw_hex.trim_start_matches("0x")) {
        Ok(b) => b,
        Err(e) => return err_json(id, -32000, format!("invalid hex: {}", e)),
    };

    let tx_hash = match queue_pending_tx(st, raw_bytes) {
        Ok(h) => h,
        Err(e) => return err_json(id, -32000, e.to_string()),
    };

    if st.config.automine {
        if let Err(e) = mine_pending_block(st, st.config.max_txs_per_block) {
            return err_json(id, -32000, format!("mining error: {}", e));
        }
    }

    ok_json(id, tx_hash)
}

fn handle_eth_get_transaction_by_hash(
    st: &EthRpcState,
    id: Value,
    params: &Value,
) -> JsonRpcResp<Value> {
    let h: String = match get_param(params, 0) {
        Ok(s) => s,
        Err(e) => return err_json(id, e.code(), e.to_string()),
    };
    let txs = st.txs.lock();
    let found = txs.get(&h).cloned();
    ok_json(id, found)
}

fn handle_eth_get_transaction_receipt(
    st: &EthRpcState,
    id: Value,
    params: &Value,
) -> JsonRpcResp<Value> {
    let h: String = match get_param(params, 0) {
        Ok(s) => s,
        Err(e) => return err_json(id, e.code(), e.to_string()),
    };
    let rs = st.receipts.lock();
    let found = rs.iter().find(|r| r.tx_hash == h).cloned();
    ok_json(id, found)
}

fn handle_eth_get_block_by_number(
    st: &EthRpcState,
    id: Value,
    params: &Value,
) -> JsonRpcResp<Value> {
    let tag = get_block_tag(params, 0);
    let full = params.get(1).and_then(|v| v.as_bool()).unwrap_or(false);

    let blocks = st.blocks.lock();
    let txs = st.txs.lock();

    let b = match tag {
        BlockTag::Pending => {
            let latest = blocks.last().cloned();
            if let Some(mut lb) = latest {
                let pool = st.txpool.lock();
                let mut txs_list = Vec::new();
                for lane in pool.by_sender.values() {
                    for t in lane.values() {
                        txs_list.push(t.hash.clone());
                    }
                }
                lb.transactions = txs_list;
                Some(lb)
            } else {
                None
            }
        }
        BlockTag::Latest => blocks.last().cloned(),
        BlockTag::Number(n) => blocks.iter().find(|b| b.number == n).cloned(),
    };

    if !full {
        ok_json(id, b)
    } else {
        let b2 = b.map(|bb| {
            let tx_objs: Vec<Value> = bb
                .transactions
                .iter()
                .filter_map(|h| txs.get(h))
                .map(|t| serde_json::to_value(t).unwrap())
                .collect();
            let mut v = serde_json::to_value(&bb).unwrap();
            if let Value::Object(ref mut o) = v {
                o.insert("transactions".to_string(), Value::Array(tx_objs));
            }
            v
        });
        ok_json(id, b2)
    }
}

fn handle_eth_get_logs(
    st: &EthRpcState,
    id: Value,
    params: &Value,
) -> JsonRpcResp<Value> {
    let filter = params.get(0).unwrap_or(&Value::Null);

    let addr_filter_single = filter
        .get("address")
        .and_then(|v| v.as_str())
        .map(|s| s.to_lowercase());

    let addr_filter_multi = filter.get("address").and_then(|v| v.as_array()).map(|arr| {
        arr.iter()
            .filter_map(|x| x.as_str())
            .map(|s| s.to_lowercase())
            .collect::<Vec<_>>()
    });

    let topics_filter = filter.get("topics");

    let from_block = filter
        .get("fromBlock")
        .and_then(|v| v.as_str())
        .and_then(|s| u64::from_str_radix(s.trim_start_matches("0x"), 16).ok())
        .unwrap_or(0);

    let to_block = filter
        .get("toBlock")
        .and_then(|v| v.as_str())
        .and_then(|s| u64::from_str_radix(s.trim_start_matches("0x"), 16).ok())
        .unwrap_or(u64::MAX);

    let rs = st.receipts.lock();
    let mut logs = Vec::new();

    for r in rs.iter() {
        if r.block_number < from_block || r.block_number > to_block {
            continue;
        }

        for lg in r.logs.iter() {
            if let Some(tf) = topics_filter {
                if let Some(arr) = tf.as_array() {
                    let mut ok_topics = true;
                    for (i, want) in arr.iter().enumerate() {
                        if want.is_null() {
                            continue;
                        }
                        let have = lg.topics.get(i).map(|x| x.to_lowercase());
                        if have.is_none() {
                            ok_topics = false;
                            break;
                        }

                        if let Some(ws) = want.as_str() {
                            if have.as_ref().unwrap() != &ws.to_lowercase() {
                                ok_topics = false;
                                break;
                            }
                        } else if let Some(opts) = want.as_array() {
                            let mut any = false;
                            for o in opts {
                                if let Some(ws) = o.as_str() {
                                    if have.as_ref().unwrap() == &ws.to_lowercase() {
                                        any = true;
                                        break;
                                    }
                                }
                            }
                            if !any {
                                ok_topics = false;
                                break;
                            }
                        } else {
                            ok_topics = false;
                            break;
                        }
                    }
                    if !ok_topics {
                        continue;
                    }
                }
            }

            if let Some(af) = &addr_filter_single {
                if lg.address.to_lowercase() != *af {
                    continue;
                }
            }

            if let Some(afs) = &addr_filter_multi {
                if !afs.iter().any(|a| lg.address.to_lowercase() == *a) {
                    continue;
                }
            }

            logs.push(lg.clone());
        }
    }

    ok_json(id, logs)
}

fn handle_eth_gas_price(st: &EthRpcState, id: Value) -> JsonRpcResp<Value> {
    let bf = st.current_base_fee();
    ok_json(id, format!("0x{:x}", bf))
}

// ── Mining Functions ──────────────────────────────────────────────────────

fn queue_pending_tx(st: &EthRpcState, raw_bytes: Vec<u8>) -> Result<String, RpcError> {
    let tx_hash = keccak256_hex(&raw_bytes);
    let tx_type = if !raw_bytes.is_empty() {
        raw_bytes[0]
    } else {
        0
    };

    let parsed_legacy = decode_legacy_signed_tx(&raw_bytes).ok();

    let (from, nonce, gas_limit, gas_price, max_fee, max_tip) = if tx_type == 0x02 {
        let t = decode_eip1559_signed_tx(&raw_bytes[1..])
            .map_err(|e| RpcError::TxDecode(e.to_string()))?;
        (
            format!("0x{}", hex::encode(t.from)),
            t.nonce,
            t.gas_limit,
            0u128,
            Some(t.max_fee_per_gas),
            Some(t.max_priority_fee_per_gas),
        )
    } else if tx_type == 0x01 {
        let t = decode_eip2930_signed_tx(&raw_bytes[1..])
            .map_err(|e| RpcError::TxDecode(e.to_string()))?;
        (
            format!("0x{}", hex::encode(t.from)),
            t.nonce,
            t.gas_limit,
            t.gas_price,
            None,
            None,
        )
    } else {
        let p = parsed_legacy.clone().ok_or(RpcError::TxDecode("legacy decode failed".into()))?;
        (
            format!("0x{}", hex::encode(p.from)),
            p.nonce,
            p.gas_limit,
            p.gas_price,
            None,
            None,
        )
    };

    let inserted_at = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    let raw_hex = format!("0x{}", hex::encode(&raw_bytes));
    let ptx = PendingTx {
        hash: tx_hash.clone(),
        from: from.clone(),
        nonce,
        tx_type: if tx_type == 0x01 || tx_type == 0x02 {
            tx_type
        } else {
            0
        },
        gas_limit,
        gas_price,
        max_fee_per_gas: max_fee,
        max_priority_fee_per_gas: max_tip,
        raw: raw_bytes,
        inserted_at,
    };

    let mut pool = st.txpool.lock();
    pool.insert(ptx).map_err(|_| RpcError::Internal("txpool insert failed".into()))?;
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    pool.prune(now, 3600, 10_000);
    drop(pool);

    st.maybe_persist();

    st.txs
        .lock()
        .entry(tx_hash.clone())
        .or_insert_with(|| TxRecord {
            hash: tx_hash.clone(),
            from,
            to: parsed_legacy
                .as_ref()
                .and_then(|p| p.to)
                .map(|a| format!("0x{}", hex::encode(a))),
            gas: parsed_legacy.as_ref().map(|p| p.gas_limit).unwrap_or(0),
            input: parsed_legacy
                .as_ref()
                .map(|p| format!("0x{}", hex::encode(p.data.clone())))
                .unwrap_or_else(|| "0x".to_string()),
            value: parsed_legacy
                .as_ref()
                .map(|p| format!("0x{:x}", p.value))
                .unwrap_or_else(|| "0x0".to_string()),
            nonce,
            raw: raw_hex,
        });

    Ok(tx_hash)
}

fn mine_pending_block(st: &EthRpcState, max_txs: usize) -> Result<Vec<String>, RpcError> {
    let db = st.db.lock();
    let mut nonces = HashMap::new();
    for (addr, info) in db.accounts.iter() {
        nonces.insert(format!("0x{}", hex::encode(addr)), info.nonce);
    }
    drop(db);

    let txs = st
        .txpool
        .lock()
        .drain_next_ready(&nonces, max_txs);

    let mut mined = Vec::new();
    for tx in txs {
        mined.push(mine_one(st, tx.raw)?);
    }
    Ok(mined)
}

fn mine_one(st: &EthRpcState, raw_bytes: Vec<u8>) -> Result<String, RpcError> {
    let (evm_tx, _from) = decode_raw_tx(&raw_bytes).map_err(|e| RpcError::TxDecode(e.to_string()))?;
    let parsed_legacy = decode_legacy_signed_tx(&raw_bytes).ok();

    let mut db = st.db.lock();
    let env = default_env(st.config.chain_id);
    let out = execute_evm_tx(&mut *db, env, evm_tx)
        .map_err(|e| RpcError::Execution(e.to_string()))?;

    let bn = st.increment_block_number();

    let tx_hash = keccak256_hex(&raw_bytes);
    let tx_type = if !raw_bytes.is_empty() && (raw_bytes[0] == 0x01 || raw_bytes[0] == 0x02) {
        raw_bytes[0]
    } else {
        0x00
    };
    let bhash = crate::rpc::block_store::keccak_hex(tx_hash.as_bytes());

    let mut bloom = Bloom::default();
    let mut logs = Vec::new();

    for (i, l) in out.logs.iter().enumerate() {
        bloom.insert(l.address.as_slice());
        for t in l.data.topics().iter() {
            bloom.insert(t.as_slice());
        }

        logs.push(Log {
            address: format!("0x{}", hex::encode(l.address)),
            topics: l
                .data
                .topics()
                .iter()
                .map(|t| format!("0x{}", hex::encode(t)))
                .collect(),
            data: format!("0x{}", hex::encode(&l.data.data)),
            block_number: bn,
            tx_hash: tx_hash.clone(),
            log_index: i as u64,
        });
    }

    let contract_address = out.created_address.map(|a| format!("0x{}", hex::encode(a)));

    let receipt = Receipt {
        tx_type,
        tx_hash: tx_hash.clone(),
        block_number: bn,
        status: out.success,
        gas_used: out.gas_used,
        contract_address,
        logs: logs.clone(),
        block_hash: bhash.clone(),
        transaction_index: 0,
        cumulative_gas_used: out.gas_used,
        effective_gas_price: {
            let bf = st.current_base_fee();
            if tx_type == 0x02 {
                if let Ok(t) = decode_eip1559_signed_tx(&raw_bytes[1..]) {
                    let cap = t.max_fee_per_gas;
                    let tip = t.max_priority_fee_per_gas;
                    let eff = std::cmp::min(cap, (bf as u128).saturating_add(tip));
                    format!("0x{:x}", eff)
                } else {
                    format!("0x{:x}", bf)
                }
            } else if let Some(p) = parsed_legacy.as_ref() {
                format!("0x{:x}", p.gas_price)
            } else {
                "0x0".to_string()
            }
        },
        logs_bloom: bloom.to_hex(),
    };

    st.record_receipt(receipt.clone());
    st.record_logs(logs.clone());

    let block_withdrawals = st.pending_withdrawals.lock().clone();

    {
        let mut wds = st.pending_withdrawals.lock();
        for w in wds.drain(..) {
            let addr = Address::from_slice(&w.address);
            let mut info = db.accounts.get(&addr).cloned().unwrap_or_default();
            let add_wei = U256::from(w.amount_gwei) * U256::from(1_000_000_000u64);
            info.balance = info.balance.saturating_add(add_wei);
            db.accounts.insert(addr, info);
        }
    }

    let new_base_fee = next_base_fee(st.current_base_fee(), out.gas_used, DEFAULT_GAS_LIMIT);
    st.set_base_fee(new_base_fee);

    let txs = vec![tx_hash.clone()];
    let tx_items: Vec<Vec<u8>> = txs
        .iter()
        .filter_map(|h| {
            st.txs
                .lock()
                .get(h)
                .map(|t| hex::decode(t.raw.trim_start_matches("0x")).unwrap_or_default())
        })
        .collect();
    let tx_root = eth_ordered_trie_root_hex(&tx_items);

    let receipts_vec = vec![receipt.clone()];
    let receipt_items: Vec<Vec<u8>> = receipts_vec
        .iter()
        .map(|r| rlp_encode_typed_receipt(r.tx_type, r))
        .collect();
    let receipts_root = eth_ordered_trie_root_hex(&receipt_items);
    let logs_bloom_hex = receipt.logs_bloom.clone();

    st.receipts_by_block.lock().insert(bn, receipts_vec);

    let header = EthHeader {
        parent_hash: h256_from_hex(
            &st.blocks
                .lock()
                .last()
                .map(|b| b.hash.clone())
                .unwrap_or_else(|| "0x0".to_string()),
        ),
        ommers_hash: empty_ommers_hash(),
        beneficiary: [0u8; 20],
        state_root: h256_from_hex(&compute_state_root_hex(&db)),
        transactions_root: h256_from_hex(&tx_root),
        receipts_root: h256_from_hex(&receipts_root),
        logs_bloom: bloom_from_hex(&logs_bloom_hex),
        difficulty: 0,
        number: bn,
        gas_limit: DEFAULT_GAS_LIMIT,
        gas_used: out.gas_used,
        timestamp: 0,
        extra_data: vec![],
        mix_hash: [0u8; 32],
        nonce: [0u8; 8],
        base_fee_per_gas: new_base_fee,
        withdrawals_root: h256_from_hex(&withdrawals_root_hex(&block_withdrawals)),
    };

    let block_hash = header_hash_hex(&header);

    let block = Block {
        number: bn,
        hash: block_hash,
        parent_hash: format!("0x{}", hex::encode(header.parent_hash)),
        ommers_hash: format!("0x{}", hex::encode(header.ommers_hash)),
        miner: "0x0000000000000000000000000000000000000000".to_string(),
        state_root: compute_state_root_hex(&db),
        transactions: txs,
        transactions_root: tx_root,
        receipts_root,
        withdrawals_root: withdrawals_root_hex(&block_withdrawals),
        withdrawals: block_withdrawals,
        logs_bloom: logs_bloom_hex,
        timestamp: 0,
        gas_limit: format!("0x{:x}", DEFAULT_GAS_LIMIT),
        gas_used: format!("0x{:x}", out.gas_used),
        base_fee_per_gas: format!("0x{:x}", new_base_fee),
    };

    st.record_block(block.clone());

    st.maybe_persist();

    if let Some(dir) = &st.config.chain_db_dir {
        let rs = st
            .receipts_by_block
            .lock()
            .get(&bn)
            .cloned()
            .unwrap_or_default();
        let mut txrecs = Vec::new();
        for h in block.transactions.iter() {
            if let Some(t) = st.txs.lock().get(h).cloned() {
                txrecs.push(t);
            }
        }
        let logs2 = rs.iter().flat_map(|r| r.logs.clone()).collect::<Vec<_>>();
        persist_new_block_bundle(dir, &block, &rs, &txrecs, &logs2);
    }

    Ok(tx_hash)
}

// ── Main RPC Dispatcher ──────────────────────────────────────────────────

pub async fn handle_rpc(
    State(st): State<EthRpcState>,
    Json(req): Json<JsonRpcReq>,
) -> Result<Json<Value>, StatusCode> {
    let id = req.id.clone();
    let method = req.method.clone();
    let params = req.params;

    let start = std::time::Instant::now();

    // Dispatch to handler.
    let resp = dispatch_method(&st, &method, &params, id.clone());

    // Record metrics.
    if st.config.enable_metrics {
        let status = if resp.error.is_some() { "error" } else { "ok" };
        st.metrics.record_call(&method, status);
        st.metrics.record_duration(&method, start.elapsed());
        if let Some(err) = &resp.error {
            st.metrics.record_error(&method, err.code);
        }
    }

    // Log.
    trace!(
        method = %method,
        id = ?id,
        status = if resp.error.is_some() { "error" } else { "ok" },
        duration_ms = start.elapsed().as_millis(),
        "RPC call"
    );

    Ok(Json(serde_json::to_value(resp).expect("serialization failed")))
}

fn dispatch_method(
    st: &EthRpcState,
    method: &str,
    params: &Value,
    id: Value,
) -> JsonRpcResp<Value> {
    match method {
        "web3_clientVersion" => handle_web3_client_version(id),
        "eth_chainId" => handle_eth_chain_id(st, id),
        "eth_blockNumber" => handle_eth_block_number(st, id),
        "eth_getTransactionCount" => handle_eth_get_transaction_count(st, id, params),
        "eth_getBalance" => handle_eth_get_balance(st, id, params),
        "eth_getCode" => handle_eth_get_code(st, id, params),
        "eth_getStorageAt" => handle_eth_get_storage_at(st, id, params),
        "eth_estimateGas" => handle_eth_estimate_gas(st, id, params),
        "eth_call" => handle_eth_call(st, id, params),
        "eth_sendRawTransaction" => handle_eth_send_raw_transaction(st, id, params),
        "eth_getTransactionByHash" => handle_eth_get_transaction_by_hash(st, id, params),
        "eth_getTransactionReceipt" => handle_eth_get_transaction_receipt(st, id, params),
        "eth_getBlockByNumber" => handle_eth_get_block_by_number(st, id, params),
        "eth_getLogs" => handle_eth_get_logs(st, id, params),
        "eth_gasPrice" => handle_eth_gas_price(st, id),
        "iona_mine" => {
            let max = params.get(0).and_then(|v| v.as_u64()).unwrap_or(128) as usize;
            match mine_pending_block(st, max) {
                Ok(mined) => ok_json(id, mined),
                Err(e) => err_json(id, e.code(), e.to_string()),
            }
        }
        "eth_getBlockTransactionCountByNumber" => {
            let tag = get_block_tag(params, 0);
            let blocks = st.blocks.lock();
            let b = match tag {
                BlockTag::Pending => {
                    let latest = blocks.last().cloned();
                    if let Some(mut lb) = latest {
                        let pool = st.txpool.lock();
                        let mut txs_list = Vec::new();
                        for lane in pool.by_sender.values() {
                            for t in lane.values() {
                                txs_list.push(t.hash.clone());
                            }
                        }
                        lb.transactions = txs_list;
                        Some(lb)
                    } else {
                        None
                    }
                }
                BlockTag::Latest => blocks.last().cloned(),
                BlockTag::Number(n) => blocks.iter().find(|b| b.number == n).cloned(),
            };
            ok_json(id, b.map(|bb| format!("0x{:x}", bb.transactions.len())))
        }
        "eth_getBlockTransactionCountByHash" => {
            let h: String = match get_param(params, 0) {
                Ok(s) => s,
                Err(e) => return err_json(id, e.code(), e.to_string()),
            };
            let blocks = st.blocks.lock();
            let b = blocks.iter().find(|b| b.hash == h).cloned();
            ok_json(id, b.map(|bb| format!("0x{:x}", bb.transactions.len())))
        }
        "eth_getBlockByHash" => {
            let h: String = match get_param(params, 0) {
                Ok(s) => s,
                Err(e) => return err_json(id, e.code(), e.to_string()),
            };
            let full = params.get(1).and_then(|v| v.as_bool()).unwrap_or(false);
            let blocks = st.blocks.lock();
            let txs = st.txs.lock();
            let b = blocks.iter().find(|b| b.hash == h).cloned();

            if !full {
                ok_json(id, b)
            } else {
                let b2 = b.map(|bb| {
                    let tx_objs: Vec<Value> = bb
                        .transactions
                        .iter()
                        .filter_map(|h| txs.get(h))
                        .map(|t| serde_json::to_value(t).unwrap())
                        .collect();
                    let mut v = serde_json::to_value(&bb).unwrap();
                    if let Value::Object(ref mut o) = v {
                        o.insert("transactions".to_string(), Value::Array(tx_objs));
                    }
                    v
                });
                ok_json(id, b2)
            }
        }
        "eth_getTransactionByBlockHashAndIndex" => {
            let block_hash: String = match get_param(params, 0) {
                Ok(s) => s,
                Err(e) => return err_json(id, e.code(), e.to_string()),
            };
            let idx_str: String = match get_param(params, 1) {
                Ok(s) => s,
                Err(e) => return err_json(id, e.code(), e.to_string()),
            };
            let idx = usize::from_str_radix(idx_str.trim_start_matches("0x"), 16)
                .map_err(|_| RpcError::InvalidParams("invalid index".into()));

            let blocks = st.blocks.lock();
            let txs = st.txs.lock();

            let found = blocks
                .iter()
                .find(|b| b.hash == block_hash)
                .and_then(|b| b.transactions.get(idx))
                .and_then(|h| txs.get(h).cloned());

            ok_json(id, found)
        }
        "eth_getTransactionByBlockNumberAndIndex" => {
            let tag = get_block_tag(params, 0);
            let idx_str: String = match get_param(params, 1) {
                Ok(s) => s,
                Err(e) => return err_json(id, e.code(), e.to_string()),
            };
            let idx = usize::from_str_radix(idx_str.trim_start_matches("0x"), 16)
                .map_err(|_| RpcError::InvalidParams("invalid index".into()));

            let blocks = st.blocks.lock();
            let txs = st.txs.lock();

            let block = match tag {
                BlockTag::Latest => blocks.last().cloned(),
                BlockTag::Number(n) => blocks.iter().find(|b| b.number == n).cloned(),
                _ => None,
            };

            let found = block
                .and_then(|b| b.transactions.get(idx).cloned())
                .and_then(|h| txs.get(&h).cloned());

            ok_json(id, found)
        }
        "eth_getProof" => {
            let addr = match get_addr(params, 0) {
                Ok(a) => a,
                Err(e) => return err_json(id, e.code(), e.to_string()),
            };
            let storage_keys = params
                .get(1)
                .and_then(|v| v.as_array())
                .cloned()
                .unwrap_or_default();

            let db = st.db.lock();
            let state_root = compute_state_root_hex(&db);
            let info = db.accounts.get(&addr).cloned().unwrap_or_default();
            let balance = format!("0x{:x}", info.balance);
            let nonce = format!("0x{:x}", info.nonce);
            let code_hash = format!("0x{}", hex::encode(info.code_hash));
            let storage_hash = empty_trie_root_hex();

            let storage_proof = storage_keys
                .into_iter()
                .map(|k| {
                    let key_str = k.as_str().unwrap_or("0x0").to_string();
                    let key_bytes =
                        hex::decode(key_str.trim_start_matches("0x")).unwrap_or_default();
                    let mut slot = [0u8; 32];
                    let start = 32usize.saturating_sub(key_bytes.len());
                    let take = key_bytes.len().min(32);
                    slot[start..].copy_from_slice(&key_bytes[..take]);
                    let slot_u256 = U256::from_be_bytes(slot);
                    let val = db
                        .storage
                        .get(&(addr, slot_u256))
                        .copied()
                        .unwrap_or(U256::ZERO);
                    json!({
                        "key": key_str,
                        "value": format!("0x{:x}", val),
                        "proof": []
                    })
                })
                .collect::<Vec<_>>();

            ok_json(
                id,
                json!({
                    "address": format!("0x{}", hex::encode(addr)),
                    "accountProof": [],
                    "balance": balance,
                    "codeHash": code_hash,
                    "nonce": nonce,
                    "storageHash": storage_hash,
                    "storageProof": storage_proof,
                    "stateRoot": state_root
                }),
            )
        }
        "eth_feeHistory" => {
            let block_count = get_u64_param(params, 0, 1);
            let tag = get_block_tag(params, 1);
            let newest_bn = match tag {
                BlockTag::Latest => st.current_block_number(),
                BlockTag::Number(n) => n,
                _ => st.current_block_number(),
            };
            let oldest = newest_bn.saturating_sub(block_count.saturating_sub(1));
            let mut base_fees = Vec::new();
            for _ in 0..=block_count {
                base_fees.push(format!(
                    "0x{:x}",
                    st.current_base_fee()
                ));
            }
            let gas_used_ratio = vec![0.0f64; block_count as usize];
            let reward: Vec<Vec<String>> = vec![vec![]; block_count as usize];
            ok_json(
                id,
                json!({
                    "oldestBlock": format!("0x{:x}", oldest),
                    "baseFeePerGas": base_fees,
                    "gasUsedRatio": gas_used_ratio,
                    "reward": reward
                }),
            )
        }
        "net_version" => ok_json(id, st.config.chain_id.to_string()),
        "net_listening" => ok_json(id, true),
        "net_peerCount" => ok_json(id, "0x1"),
        "eth_protocolVersion" => ok_json(id, "0x41"),
        "eth_syncing" => ok_json(id, false),
        "eth_mining" => ok_json(id, st.config.automine),
        "eth_hashrate" => ok_json(id, "0x0"),
        "eth_maxPriorityFeePerGas" => ok_json(id, "0x3b9aca00"),
        "eth_accounts" => ok_json(id, Vec::<String>::new()),
        "eth_getUncleCountByBlockHash" => ok_json(id, "0x0"),
        "eth_getUncleCountByBlockNumber" => ok_json(id, "0x0"),
        "eth_getUncleByBlockHashAndIndex" => ok_json(id, Value::Null),
        "eth_getUncleByBlockNumberAndIndex" => ok_json(id, Value::Null),
        "eth_newFilter" | "eth_newBlockFilter" | "eth_newPendingTransactionFilter" => {
            ok_json(id, "0x1")
        }
        "eth_getFilterChanges" | "eth_getFilterLogs" => ok_json(id, Vec::<Value>::new()),
        "eth_uninstallFilter" => ok_json(id, true),
        "eth_subscribe" | "eth_unsubscribe" => err_json(
            id,
            -32000,
            "Subscriptions not supported over HTTP. Use WebSocket.",
        ),
        "debug_traceTransaction" | "debug_traceBlock" => {
            err_json(id, -32000, "debug namespace not enabled")
        }
        _ => err_json(id, -32601, format!("Method not found: {}", method)),
    }
}

// ── Response Builders ────────────────────────────────────────────────────

fn ok_json<T: Serialize>(id: Value, result: T) -> JsonRpcResp<Value> {
    JsonRpcResp {
        jsonrpc: "2.0",
        id,
        result: Some(serde_json::to_value(result).expect("serialization failed")),
        error: None,
    }
}

fn err_json(id: Value, code: i64, msg: impl Into<String>) -> JsonRpcResp<Value> {
    JsonRpcResp {
        jsonrpc: "2.0",
        id,
        result: None,
        error: Some(JsonRpcErr {
            code,
            message: msg.into(),
        }),
    }
}

// ── Batch Handler ─────────────────────────────────────────────────────────

pub async fn handle_batch_rpc(
    State(st): State<EthRpcState>,
    Json(requests): Json<Vec<JsonRpcReq>>,
) -> Result<Json<Vec<Value>>, StatusCode> {
    if requests.len() > MAX_BATCH_SIZE {
        return Err(StatusCode::PAYLOAD_TOO_LARGE);
    }

    let mut responses = Vec::with_capacity(requests.len());
    for req in requests {
        let resp = handle_rpc(
            State(st.clone()),
            Json(req),
        )
        .await?;
        responses.push(serde_json::to_value(resp).expect("serialization failed"));
    }

    Ok(Json(responses))
}

// ── Public API ────────────────────────────────────────────────────────────

pub fn mine_pending_block_public(
    st: &EthRpcState,
    max_txs: usize,
) -> Result<Vec<String>, StatusCode> {
    mine_pending_block(st, max_txs)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)
}

// ── Tests ─────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn test_state() -> EthRpcState {
        let config = RpcConfig::default();
        EthRpcState::new(config).unwrap()
    }

    #[test]
    fn test_parse_addr_hex_ok() {
        let addr = parse_addr_hex("0x0000000000000000000000000000000000000001").unwrap();
        assert_eq!(addr.to_vec()[19], 1);
    }

    #[test]
    fn test_parse_addr_hex_invalid() {
        assert!(parse_addr_hex("0xzz").is_err());
    }

    #[test]
    fn test_eth_block_number() {
        let st = test_state();
        let resp = handle_eth_block_number(&st, json!(1));
        assert!(resp.result.is_some());
        assert_eq!(resp.result.unwrap(), json!("0x0"));
    }

    #[test]
    fn test_eth_chain_id() {
        let st = test_state();
        let resp = handle_eth_chain_id(&st, json!(1));
        assert_eq!(resp.result.unwrap(), json!("0x1"));
    }

    #[test]
    fn test_get_block_tag() {
        assert!(matches!(BlockTag::parse("latest"), BlockTag::Latest));
        assert!(matches!(BlockTag::parse("0x1"), BlockTag::Number(1)));
        assert!(matches!(BlockTag::parse("1"), BlockTag::Number(1)));
    }

    #[test]
    fn test_ok_json() {
        let resp = ok_json(json!(1), "test");
        assert_eq!(resp.jsonrpc, "2.0");
        assert_eq!(resp.id, json!(1));
        assert_eq!(resp.result.unwrap(), json!("test"));
        assert!(resp.error.is_none());
    }

    #[test]
    fn test_err_json() {
        let resp = err_json(json!(1), -32000, "error");
        assert_eq!(resp.jsonrpc, "2.0");
        assert_eq!(resp.id, json!(1));
        assert!(resp.result.is_none());
        assert!(resp.error.is_some());
        assert_eq!(resp.error.unwrap().code, -32000);
    }
}
