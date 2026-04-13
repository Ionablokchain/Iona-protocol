use crate::evm::db::MemDb;
use crate::evm::executor::execute_evm_tx;
use crate::evm::executor_env::default_env;
use crate::types::tx_evm::EvmTx;

use axum::{extract::State, http::StatusCode, Json};
use revm::primitives::{Address, Bytes, U256};
use revm::Database;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

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

#[derive(Clone)]
pub struct EthRpcState {
    pub db: Arc<Mutex<MemDb>>,
    pub chain_id: u64,
    pub block_number: Arc<Mutex<u64>>,
    pub base_fee: Arc<Mutex<u64>>,
    pub receipts: Arc<Mutex<Vec<Receipt>>>,
    pub txs: Arc<Mutex<std::collections::HashMap<String, TxRecord>>>,
    pub blocks: Arc<Mutex<Vec<Block>>>,
    pub receipts_by_block: Arc<Mutex<std::collections::HashMap<u64, Vec<Receipt>>>>,
    pub all_logs: Arc<Mutex<Vec<Log>>>,
    pub txpool: Arc<Mutex<TxPool>>,
    pub automine: bool,
    pub pending_withdrawals: Arc<Mutex<Vec<Withdrawal>>>,
    pub persist_dir: Option<String>,
    pub chain_db_dir: Option<String>,
    pub last_persist_secs: Arc<Mutex<u64>>,
    pub persist_interval_secs: u64,
}

impl Default for EthRpcState {
    fn default() -> Self {
        Self {
            db: Arc::new(Mutex::new(MemDb::default())),
            chain_id: 1,
            block_number: Arc::new(Mutex::new(0)),
            base_fee: Arc::new(Mutex::new(0)),
            receipts: Arc::new(Mutex::new(vec![])),
            txs: Arc::new(Mutex::new(HashMap::new())),
            blocks: Arc::new(Mutex::new(vec![])),
            receipts_by_block: Arc::new(Mutex::new(HashMap::new())),
            all_logs: Arc::new(Mutex::new(vec![])),
            txpool: Arc::new(Mutex::new(TxPool::default())),
            automine: true,
            pending_withdrawals: Arc::new(Mutex::new(vec![])),
            persist_dir: None,
            chain_db_dir: None,
            last_persist_secs: Arc::new(Mutex::new(0)),
            persist_interval_secs: 5,
        }
    }
}

#[derive(Debug, Deserialize)]
pub struct JsonRpcReq {
    pub jsonrpc: String,
    pub id: serde_json::Value,
    pub method: String,
    #[serde(default)]
    pub params: serde_json::Value,
}

#[derive(Debug, Serialize)]
pub struct JsonRpcResp<T: Serialize> {
    pub jsonrpc: &'static str,
    pub id: serde_json::Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<T>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<JsonRpcErr>,
}

#[derive(Debug, Serialize)]
pub struct JsonRpcErr {
    pub code: i64,
    pub message: String,
}

fn ok_json(id: serde_json::Value, result: impl Serialize) -> JsonRpcResp<Value> {
    JsonRpcResp {
        jsonrpc: "2.0",
        id,
        result: Some(serde_json::to_value(result).expect("serialization failed")),
        error: None,
    }
}

fn err_json(id: serde_json::Value, code: i64, msg: impl Into<String>) -> JsonRpcResp<Value> {
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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Log {
    pub address: String,
    pub topics: Vec<String>,
    pub data: String,
    pub block_number: u64,
    pub tx_hash: String,
    pub log_index: u64,
}

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

fn keccak256_hex(data: &[u8]) -> String {
    format!("0x{}", hex::encode(crate::rpc::tx_decode::keccak256(data)))
}

fn empty_trie_root_hex() -> String {
    use sha3::{Digest, Keccak256};
    let mut h = Keccak256::new();
    h.update([0x80u8]);
    format!("0x{}", hex::encode(h.finalize()))
}

fn queue_pending_tx(st: &EthRpcState, raw_bytes: Vec<u8>) -> Result<String, StatusCode> {
    let tx_hash = keccak256_hex(&raw_bytes);
    let tx_type = if !raw_bytes.is_empty() {
        raw_bytes[0]
    } else {
        0
    };

    let parsed_legacy = crate::rpc::tx_decode::decode_legacy_signed_tx(&raw_bytes).ok();

    let (from, nonce, gas_limit, gas_price, max_fee, max_tip) = if tx_type == 0x02 {
        let t = crate::rpc::tx_decode::decode_eip1559_signed_tx(&raw_bytes[1..])
            .map_err(|_| StatusCode::BAD_REQUEST)?;
        (
            format!("0x{}", hex::encode(t.from)),
            t.nonce,
            t.gas_limit,
            0u128,
            Some(t.max_fee_per_gas),
            Some(t.max_priority_fee_per_gas),
        )
    } else if tx_type == 0x01 {
        let t = crate::rpc::tx_decode::decode_eip2930_signed_tx(&raw_bytes[1..])
            .map_err(|_| StatusCode::BAD_REQUEST)?;
        (
            format!("0x{}", hex::encode(t.from)),
            t.nonce,
            t.gas_limit,
            t.gas_price,
            None,
            None,
        )
    } else {
        let p = parsed_legacy.clone().ok_or(StatusCode::BAD_REQUEST)?;
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

    let mut pool = st.txpool.lock().expect("txpool lock poisoned");
    pool.insert(ptx).map_err(|_| StatusCode::BAD_REQUEST)?;
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    pool.prune(now, 3600, 10_000);
    drop(pool);

    maybe_persist(st);

    st.txs
        .lock()
        .expect("txs lock poisoned")
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
            raw: raw_hex.clone(),
        });

    Ok(tx_hash)
}

fn mine_one(st: &EthRpcState, raw_bytes: Vec<u8>) -> Result<String, StatusCode> {
    let (evm_tx, _from) =
        crate::rpc::tx_decode::decode_raw_tx(&raw_bytes).map_err(|_| StatusCode::BAD_REQUEST)?;
    let parsed_legacy = crate::rpc::tx_decode::decode_legacy_signed_tx(&raw_bytes).ok();

    let mut db = st.db.lock().expect("db lock poisoned");
    let env = default_env(st.chain_id);
    let out = execute_evm_tx(&mut *db, env, evm_tx).map_err(|_| StatusCode::BAD_REQUEST)?;

    let mut bn = st.block_number.lock().expect("block_number lock poisoned");
    *bn += 1;

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
            block_number: *bn,
            tx_hash: tx_hash.clone(),
            log_index: i as u64,
        });
    }

    let contract_address = out.created_address.map(|a| format!("0x{}", hex::encode(a)));

    let receipt = Receipt {
        tx_type,
        tx_hash: tx_hash.clone(),
        block_number: *bn,
        status: out.success,
        gas_used: out.gas_used,
        contract_address,
        logs,
        block_hash: bhash.clone(),
        transaction_index: 0,
        cumulative_gas_used: out.gas_used,
        effective_gas_price: {
            let bf = *st.base_fee.lock().expect("base_fee lock poisoned");
            if tx_type == 0x02 {
                if let Ok(t) = crate::rpc::tx_decode::decode_eip1559_signed_tx(&raw_bytes[1..]) {
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

    st.receipts
        .lock()
        .expect("receipts lock poisoned")
        .push(receipt.clone());

    st.all_logs
        .lock()
        .expect("all_logs lock poisoned")
        .extend(receipt.logs.clone());

    let block_withdrawals = st
        .pending_withdrawals
        .lock()
        .expect("pending_withdrawals lock poisoned")
        .clone();

    {
        let mut wds = st
            .pending_withdrawals
            .lock()
            .expect("pending_withdrawals lock poisoned");
        for w in wds.drain(..) {
            let addr = Address::from_slice(&w.address);
            let mut info = db.accounts.get(&addr).cloned().unwrap_or_default();
            let add_wei = U256::from(w.amount_gwei) * U256::from(1_000_000_000u64);
            info.balance = info.balance.saturating_add(add_wei);
            db.accounts.insert(addr, info);
        }
    }

    {
        let mut bf = st.base_fee.lock().expect("base_fee lock poisoned");
        *bf = next_base_fee(*bf, out.gas_used, 30_000_000);
    }

    let txs = vec![tx_hash.clone()];
    let tx_items: Vec<Vec<u8>> = txs
        .iter()
        .filter_map(|h| {
            st.txs
                .lock()
                .expect("txs lock poisoned")
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

    st.receipts_by_block
        .lock()
        .expect("receipts_by_block lock poisoned")
        .insert(*bn, receipts_vec);

    let header = EthHeader {
        parent_hash: h256_from_hex(
            &st.blocks
                .lock()
                .expect("blocks lock poisoned")
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
        number: *bn,
        gas_limit: 30_000_000,
        gas_used: out.gas_used,
        timestamp: 0,
        extra_data: vec![],
        mix_hash: [0u8; 32],
        nonce: [0u8; 8],
        base_fee_per_gas: *st.base_fee.lock().expect("base_fee lock poisoned"),
        withdrawals_root: h256_from_hex(&withdrawals_root_hex(&block_withdrawals)),
    };

    let block_hash = header_hash_hex(&header);

    st.blocks.lock().expect("blocks lock poisoned").push(Block {
        number: *bn,
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
        gas_limit: "0x1c9c380".to_string(),
        gas_used: format!("0x{:x}", out.gas_used),
        base_fee_per_gas: format!(
            "0x{:x}",
            *st.base_fee.lock().expect("base_fee lock poisoned")
        ),
    });

    maybe_persist(st);

    if let Some(dir) = st.chain_db_dir.as_ref() {
        let b = st
            .blocks
            .lock()
            .expect("blocks lock poisoned")
            .last()
            .cloned()
            .unwrap();
        let rs = st
            .receipts_by_block
            .lock()
            .expect("receipts_by_block lock poisoned")
            .get(&b.number)
            .cloned()
            .unwrap_or_default();
        let mut txrecs = Vec::new();
        for h in b.transactions.iter() {
            if let Some(t) = st.txs.lock().expect("txs lock poisoned").get(h).cloned() {
                txrecs.push(t);
            }
        }
        let logs = rs.iter().flat_map(|r| r.logs.clone()).collect::<Vec<_>>();
        persist_new_block_bundle(dir, &b, &rs, &txrecs, &logs);
    }

    Ok(tx_hash)
}

fn mine_pending_block(st: &EthRpcState, max_txs: usize) -> Result<Vec<String>, StatusCode> {
    let db = st.db.lock().expect("db lock poisoned");
    let mut nonces = HashMap::new();
    for (addr, info) in db.accounts.iter() {
        nonces.insert(format!("0x{}", hex::encode(addr)), info.nonce);
    }
    drop(db);

    let txs = st
        .txpool
        .lock()
        .expect("txpool lock poisoned")
        .drain_next_ready(&nonces, max_txs);

    let mut mined = Vec::new();
    for tx in txs {
        mined.push(mine_one(st, tx.raw)?);
    }
    Ok(mined)
}

fn mine_one_on_db(db: &mut MemDb, chain_id: u64, raw_bytes: &[u8]) -> Option<u64> {
    let (evm_tx, _from) = crate::rpc::tx_decode::decode_raw_tx(raw_bytes).ok()?;
    let env = default_env(chain_id);
    let out = execute_evm_tx(db, env, evm_tx).ok()?;
    Some(out.gas_used)
}

pub async fn handle_rpc(
    State(st): State<EthRpcState>,
    Json(req): Json<JsonRpcReq>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    let id = req.id.clone();
    let method = req.method.as_str();

    let resp = match method {
        "web3_clientVersion" => ok_json(id, "iona/MEGA-v6"),
        "eth_chainId" => ok_json(id, format!("0x{:x}", st.chain_id)),
        "eth_blockNumber" => {
            let n = *st.block_number.lock().expect("block_number lock poisoned");
            ok_json(id, format!("0x{:x}", n))
        }
        "eth_getTransactionCount" => {
            let addr = get_addr(&req.params, 0)?;
            let tag = req
                .params
                .get(1)
                .and_then(|v| v.as_str())
                .unwrap_or("latest");
            let ahex = format!("0x{}", hex::encode(addr));
            let db = st.db.lock().expect("db lock poisoned");
            let base = db.accounts.get(&addr).map(|i| i.nonce).unwrap_or(0);
            drop(db);

            if tag == "pending" {
                let extra = st
                    .txpool
                    .lock()
                    .expect("txpool lock poisoned")
                    .contiguous_from(&ahex, base);
                ok_json(id, format!("0x{:x}", base + extra))
            } else {
                ok_json(id, format!("0x{:x}", base))
            }
        }
        "eth_getBalance" => {
            let addr = get_addr(&req.params, 0)?;
            let db = st.db.lock().expect("db lock poisoned");
            let bal = db
                .accounts
                .get(&addr)
                .map(|a| a.balance)
                .unwrap_or(U256::ZERO);
            ok_json(id, u256_hex(bal))
        }
        "eth_getCode" => {
            let addr = get_addr(&req.params, 0)?;
            let db = st.db.lock().expect("db lock poisoned");
            let info = db.accounts.get(&addr).cloned();
            let code = info
                .and_then(|i| db.code.get(&i.code_hash).map(|c| c.bytes().clone()))
                .unwrap_or_else(Bytes::new);
            ok_json(id, format!("0x{}", hex::encode(code)))
        }
        "eth_getStorageAt" => {
            let addr = get_addr(&req.params, 0)?;
            let key = get_h256_as_u256(&req.params, 1)?;
            let mut db = st.db.lock().expect("db lock poisoned");
            let v = db.storage(addr, key).map_err(|_| StatusCode::BAD_REQUEST)?;
            ok_json(id, u256_hex(v))
        }
        "eth_estimateGas" => {
            let call = req.params.get(0).ok_or(StatusCode::BAD_REQUEST)?;
            let to = parse_addr_hex(call.get("to").and_then(|v| v.as_str()).unwrap_or("0x0"))
                .map_err(|_| StatusCode::BAD_REQUEST)?;
            let data_hex = call.get("data").and_then(|v| v.as_str()).unwrap_or("0x");
            let data = hex::decode(data_hex.trim_start_matches("0x")).unwrap_or_default();

            let mut db = st.db.lock().expect("db lock poisoned");
            let env = default_env(st.chain_id);
            let gas_limit = 10_000_000u64;
            let tx = EvmTx::Legacy {
                from: [0u8; 20],
                to: Some(addr20(to)),
                nonce: 0,
                gas_limit,
                gas_price: 0,
                value: 0,
                data,
                chain_id: st.chain_id,
            };
            let out = execute_evm_tx(&mut *db, env, tx).map_err(|_| StatusCode::BAD_REQUEST)?;
            let est = (out.gas_used.saturating_add(25_000)).min(gas_limit);
            ok_json(id, format!("0x{:x}", est))
        }
        "eth_getProof" => {
            let addr = get_addr(&req.params, 0)?;
            let storage_keys = req
                .params
                .get(1)
                .and_then(|v| v.as_array())
                .cloned()
                .unwrap_or_default();

            let db = st.db.lock().expect("db lock poisoned");
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
            let block_count = req
                .params
                .get(0)
                .and_then(|v| v.as_str())
                .and_then(|s| u64::from_str_radix(s.trim_start_matches("0x"), 16).ok())
                .unwrap_or(1);
            let newest = req
                .params
                .get(1)
                .and_then(|v| v.as_str())
                .unwrap_or("latest");
            let newest_bn = if newest == "latest" {
                *st.block_number.lock().expect("block_number lock poisoned")
            } else {
                u64::from_str_radix(newest.trim_start_matches("0x"), 16).unwrap_or(0)
            };
            let oldest = newest_bn.saturating_sub(block_count.saturating_sub(1));
            let mut base_fees = Vec::new();
            for _ in 0..=block_count {
                base_fees.push(format!(
                    "0x{:x}",
                    *st.base_fee.lock().expect("base_fee lock poisoned")
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
        "eth_call" => {
            let call = req.params.get(0).ok_or(StatusCode::BAD_REQUEST)?;
            let to = parse_addr_hex(call.get("to").and_then(|v| v.as_str()).unwrap_or("0x0"))
                .map_err(|_| StatusCode::BAD_REQUEST)?;
            let data_hex = call.get("data").and_then(|v| v.as_str()).unwrap_or("0x");
            let data = hex::decode(data_hex.trim_start_matches("0x")).unwrap_or_default();

            let mut db = st.db.lock().expect("db lock poisoned");
            let env = default_env(st.chain_id);
            let tx = EvmTx::Legacy {
                from: [0u8; 20],
                to: Some(addr20(to)),
                nonce: 0,
                gas_limit: 1_000_000,
                gas_price: 0,
                value: 0,
                data,
                chain_id: st.chain_id,
            };
            let out = execute_evm_tx(&mut *db, env, tx).map_err(|_| StatusCode::BAD_REQUEST)?;
            ok_json(id, format!("0x{}", hex::encode(out.return_data)))
        }
        "iona_mine" => {
            let max = req.params.get(0).and_then(|v| v.as_u64()).unwrap_or(128) as usize;
            let mined = mine_pending_block(&st, max)?;
            ok_json(id, mined)
        }
        "eth_sendRawTransaction" => {
            let raw = req
                .params
                .get(0)
                .and_then(|v| v.as_str())
                .ok_or(StatusCode::BAD_REQUEST)?;
            let raw_bytes =
                hex::decode(raw.trim_start_matches("0x")).map_err(|_| StatusCode::BAD_REQUEST)?;
            let tx_hash = queue_pending_tx(&st, raw_bytes.clone())?;
            if st.automine {
                let _ = mine_pending_block(&st, 1)?;
            }
            ok_json(id, tx_hash)
        }
        "eth_getTransactionByHash" => {
            let h = req
                .params
                .get(0)
                .and_then(|v| v.as_str())
                .unwrap_or_default()
                .to_string();
            let txs = st.txs.lock().expect("txs lock poisoned");
            let found = txs.get(&h).cloned();
            ok_json(id, found)
        }
        "eth_getTransactionReceipt" => {
            let h = req
                .params
                .get(0)
                .and_then(|v| v.as_str())
                .unwrap_or_default()
                .to_string();
            let rs = st.receipts.lock().expect("receipts lock poisoned");
            let found = rs.iter().find(|r| r.tx_hash == h).cloned();
            ok_json(id, found)
        }
        "eth_getBlockByNumber" => {
            let tag = req
                .params
                .get(0)
                .and_then(|v| v.as_str())
                .unwrap_or("latest");
            let full = req.params.get(1).and_then(|v| v.as_bool()).unwrap_or(false);
            let blocks = st.blocks.lock().expect("blocks lock poisoned");
            let txs = st.txs.lock().expect("txs lock poisoned");

            let b = if tag == "pending" {
                let latest = blocks.last().cloned();
                if let Some(mut lb) = latest {
                    let pool = st.txpool.lock().expect("txpool lock poisoned");
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
            } else if tag == "latest" {
                blocks.last().cloned()
            } else {
                let n = u64::from_str_radix(tag.trim_start_matches("0x"), 16).unwrap_or(0);
                blocks.iter().find(|b| b.number == n).cloned()
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
        "eth_getBlockTransactionCountByNumber" => {
            let tag = req
                .params
                .get(0)
                .and_then(|v| v.as_str())
                .unwrap_or("latest");
            let blocks = st.blocks.lock().expect("blocks lock poisoned");

            let b = if tag == "pending" {
                let latest = blocks.last().cloned();
                if let Some(mut lb) = latest {
                    let pool = st.txpool.lock().expect("txpool lock poisoned");
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
            } else if tag == "latest" {
                blocks.last().cloned()
            } else {
                let n = u64::from_str_radix(tag.trim_start_matches("0x"), 16).unwrap_or(0);
                blocks.iter().find(|b| b.number == n).cloned()
            };

            ok_json(id, b.map(|bb| format!("0x{:x}", bb.transactions.len())))
        }
        "eth_getBlockTransactionCountByHash" => {
            let h = req
                .params
                .get(0)
                .and_then(|v| v.as_str())
                .unwrap_or_default()
                .to_string();
            let blocks = st.blocks.lock().expect("blocks lock poisoned");
            let b = blocks.iter().find(|b| b.hash == h).cloned();
            ok_json(id, b.map(|bb| format!("0x{:x}", bb.transactions.len())))
        }
        "eth_getBlockByHash" => {
            let h = req
                .params
                .get(0)
                .and_then(|v| v.as_str())
                .unwrap_or_default()
                .to_string();
            let full = req.params.get(1).and_then(|v| v.as_bool()).unwrap_or(false);
            let blocks = st.blocks.lock().expect("blocks lock poisoned");
            let txs = st.txs.lock().expect("txs lock poisoned");
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
        "eth_getLogs" => {
            let filter = req.params.get(0).unwrap_or(&Value::Null);

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

            let rs = st.receipts.lock().expect("receipts lock poisoned");
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
        "net_version" => ok_json(id, st.chain_id.to_string()),
        "net_listening" => ok_json(id, true),
        "net_peerCount" => ok_json(id, "0x1"),
        "eth_protocolVersion" => ok_json(id, "0x41"),
        "eth_syncing" => ok_json(id, false),
        "eth_mining" => ok_json(id, st.automine),
        "eth_hashrate" => ok_json(id, "0x0"),
        "eth_gasPrice" => {
            let bf = st.base_fee.lock().expect("base_fee lock poisoned");
            ok_json(id, format!("0x{:x}", *bf))
        }
        "eth_maxPriorityFeePerGas" => ok_json(id, "0x3b9aca00"),
        "eth_accounts" => ok_json(id, Vec::<String>::new()),
        "eth_getUncleCountByBlockHash" => ok_json(id, "0x0"),
        "eth_getUncleCountByBlockNumber" => ok_json(id, "0x0"),
        "eth_getUncleByBlockHashAndIndex" => ok_json(id, Value::Null),
        "eth_getUncleByBlockNumberAndIndex" => ok_json(id, Value::Null),
        "eth_getTransactionByBlockHashAndIndex" => {
            let block_hash = req
                .params
                .get(0)
                .and_then(|v| v.as_str())
                .unwrap_or_default();
            let idx_str = req.params.get(1).and_then(|v| v.as_str()).unwrap_or("0x0");
            let idx = usize::from_str_radix(idx_str.trim_start_matches("0x"), 16).unwrap_or(0);

            let blocks = st.blocks.lock().expect("blocks lock poisoned");
            let txs = st.txs.lock().expect("txs lock poisoned");

            let found = blocks
                .iter()
                .find(|b| b.hash == block_hash)
                .and_then(|b| b.transactions.get(idx))
                .and_then(|h| txs.get(h).cloned());

            ok_json(id, found)
        }
        "eth_getTransactionByBlockNumberAndIndex" => {
            let tag = req
                .params
                .get(0)
                .and_then(|v| v.as_str())
                .unwrap_or("latest");
            let idx_str = req.params.get(1).and_then(|v| v.as_str()).unwrap_or("0x0");
            let idx = usize::from_str_radix(idx_str.trim_start_matches("0x"), 16).unwrap_or(0);

            let blocks = st.blocks.lock().expect("blocks lock poisoned");
            let txs = st.txs.lock().expect("txs lock poisoned");

            let block = if tag == "latest" {
                blocks.last().cloned()
            } else {
                let n = u64::from_str_radix(tag.trim_start_matches("0x"), 16).unwrap_or(0);
                blocks.iter().find(|b| b.number == n).cloned()
            };

            let found = block
                .and_then(|b| b.transactions.get(idx).cloned())
                .and_then(|h| txs.get(&h).cloned());

            ok_json(id, found)
        }
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
    };

    Ok(Json(
        serde_json::to_value(resp).expect("serialization failed"),
    ))
}

fn get_addr(params: &serde_json::Value, idx: usize) -> Result<Address, StatusCode> {
    let s = params
        .get(idx)
        .and_then(|v| v.as_str())
        .ok_or(StatusCode::BAD_REQUEST)?;
    parse_addr_hex(s).map_err(|_| StatusCode::BAD_REQUEST)
}

fn parse_addr_hex(s: &str) -> Result<Address, ()> {
    let bytes = hex::decode(s.trim_start_matches("0x")).map_err(|_| ())?;
    let mut a = [0u8; 20];
    if bytes.len() > 20 {
        return Err(());
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

fn get_h256_as_u256(params: &serde_json::Value, idx: usize) -> Result<U256, StatusCode> {
    let s = params
        .get(idx)
        .and_then(|v| v.as_str())
        .ok_or(StatusCode::BAD_REQUEST)?;
    let bytes = hex::decode(s.trim_start_matches("0x")).map_err(|_| StatusCode::BAD_REQUEST)?;
    if bytes.len() > 32 {
        return Err(StatusCode::BAD_REQUEST);
    }
    let mut b = [0u8; 32];
    b[32 - bytes.len()..].copy_from_slice(&bytes);
    Ok(U256::from_be_bytes(b))
}

fn u256_hex(v: U256) -> String {
    format!("0x{:x}", v)
}

pub fn mine_pending_block_public(
    st: &EthRpcState,
    max_txs: usize,
) -> Result<Vec<String>, axum::http::StatusCode> {
    mine_pending_block(st, max_txs)
}
