//! State persistence — IONA v30.
//!
//! Provides:
//! - `save_snapshot()` / `load_snapshot()` — atomic JSON persistence
//! - `apply_snapshot_to_state()` — restore state after restart
//! - `maybe_persist()` — throttled auto-persist on every block
//! - `load_head()` — load just the block number (fast startup check)
//! - `persist_evm_accounts()` — persist MemDb accounts to disk
//! - `load_evm_accounts()` — reload MemDb accounts on restart

use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::evm::db::MemDb;
use crate::rpc::eth_rpc::{Block, EthRpcState, Receipt, TxRecord};
use crate::rpc::txpool::TxPool;
use crate::rpc::withdrawals::Withdrawal;
use revm::primitives::{AccountInfo, Address, Bytecode, B256, U256};

// ── Paths ─────────────────────────────────────────────────────────────────

fn snapshot_path(dir: &Path) -> PathBuf {
    dir.join("state_snapshot.json")
}
fn snapshot_tmp_path(dir: &Path) -> PathBuf {
    dir.join("state_snapshot.json.tmp")
}
fn head_path(dir: &Path) -> PathBuf {
    dir.join("head.json")
}
fn accounts_path(dir: &Path) -> PathBuf {
    dir.join("evm_accounts.json")
}

// ── Full snapshot ─────────────────────────────────────────────────────────

/// Full EVM RPC state snapshot — serializable to disk.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StateSnapshot {
    pub schema_version: u32,
    pub chain_id: u64,
    pub block_number: u64,
    pub base_fee: u64,
    pub blocks: Vec<Block>,
    pub receipts: Vec<Receipt>,
    pub txs: std::collections::HashMap<String, TxRecord>,
    pub receipts_by_block: std::collections::HashMap<u64, Vec<Receipt>>,
    pub pending_withdrawals: Vec<Withdrawal>,
    pub txpool: TxPool,
}

/// Load a state snapshot from disk.
/// Returns `Ok(None)` if no snapshot exists yet (fresh node).
pub fn load_snapshot(dir: impl AsRef<Path>) -> io::Result<Option<StateSnapshot>> {
    let p = snapshot_path(dir.as_ref());
    if !p.exists() {
        return Ok(None);
    }
    let data = fs::read_to_string(&p)?;
    let snap: StateSnapshot = serde_json::from_str(&data)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;
    Ok(Some(snap))
}

/// Save a state snapshot atomically (write to .tmp, then rename).
///
/// Atomic write prevents corrupted state on crash mid-write.
pub fn save_snapshot(dir: impl AsRef<Path>, snap: &StateSnapshot) -> io::Result<()> {
    let dir = dir.as_ref();
    fs::create_dir_all(dir)?;
    let tmp = snapshot_tmp_path(dir);
    let final_path = snapshot_path(dir);

    let data = serde_json::to_string_pretty(snap)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;

    fs::write(&tmp, &data)?;
    fs::rename(&tmp, &final_path)?; // atomic on POSIX
    Ok(())
}

/// Construct a snapshot from live EthRpcState.
pub fn snapshot_from_state(st: &EthRpcState) -> StateSnapshot {
    StateSnapshot {
        schema_version: 1,
        chain_id: st.chain_id,
        block_number: *st.block_number.lock().unwrap(),
        base_fee: *st.base_fee.lock().unwrap(),
        blocks: st.blocks.lock().unwrap().clone(),
        receipts: st.receipts.lock().unwrap().clone(),
        txs: st.txs.lock().unwrap().clone(),
        receipts_by_block: st.receipts_by_block.lock().unwrap().clone(),
        pending_withdrawals: st.pending_withdrawals.lock().unwrap().clone(),
        txpool: st.txpool.lock().unwrap().clone(),
    }
}

/// Apply a snapshot to a live EthRpcState (called at startup after loading).
pub fn apply_snapshot_to_state(st: &mut EthRpcState, snap: StateSnapshot) {
    st.chain_id = snap.chain_id;
    *st.block_number.lock().unwrap() = snap.block_number;
    *st.base_fee.lock().unwrap() = snap.base_fee;
    *st.blocks.lock().unwrap() = snap.blocks;
    *st.receipts.lock().unwrap() = snap.receipts;
    *st.txs.lock().unwrap() = snap.txs;
    *st.receipts_by_block.lock().unwrap() = snap.receipts_by_block;
    *st.pending_withdrawals.lock().unwrap() = snap.pending_withdrawals;
    *st.txpool.lock().unwrap() = snap.txpool;
    tracing::info!(
        block_number = snap.block_number,
        chain_id = snap.chain_id,
        "State snapshot applied — node resumed from persisted state"
    );
}

// ── Throttled auto-persist ────────────────────────────────────────────────

/// Best-effort throttled persistence — call after each block commit.
///
/// Skips write if `persist_interval_secs` hasn't elapsed since last write.
/// Never panics — errors are logged but not propagated.
pub fn maybe_persist(st: &EthRpcState) {
    let Some(dir) = st.persist_dir.as_ref() else {
        return;
    };
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    {
        let mut last = st.last_persist_secs.lock().unwrap();
        if now.saturating_sub(*last) < st.persist_interval_secs {
            return;
        }
        *last = now;
    }
    let snap = snapshot_from_state(st);
    if let Err(e) = save_snapshot(dir, &snap) {
        tracing::warn!(error = %e, "State snapshot write failed (non-fatal)");
    }
}

// ── Head-only fast load ───────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HeadRecord {
    pub block_number: u64,
    pub block_hash: String,
    pub timestamp: u64,
}

/// Persist just the head pointer (for fast startup height check).
pub fn save_head(dir: impl AsRef<Path>, number: u64, hash: &str) -> io::Result<()> {
    let dir = dir.as_ref();
    fs::create_dir_all(dir)?;
    let head = HeadRecord {
        block_number: number,
        block_hash: hash.to_string(),
        timestamp: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs(),
    };
    let data = serde_json::to_string(&head)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;
    fs::write(head_path(dir), data)?;
    Ok(())
}

/// Load just the head block number (fast — doesn't load full snapshot).
pub fn load_head(dir: impl AsRef<Path>) -> io::Result<Option<HeadRecord>> {
    let p = head_path(dir.as_ref());
    if !p.exists() {
        return Ok(None);
    }
    let data = fs::read_to_string(&p)?;
    let head: HeadRecord = serde_json::from_str(&data)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;
    Ok(Some(head))
}

// ── EVM account persistence ───────────────────────────────────────────────

/// Serializable account info (MemDb → disk format).
#[derive(Debug, Clone, Serialize, Deserialize)]
struct PersistedAccount {
    address: String, // 0x hex
    nonce: u64,
    balance: String,   // decimal string (U256 can be large)
    code_hash: String, // 0x hex B256
    #[serde(default)]
    storage: Vec<(String, String)>, // (slot_hex, value_hex)
}

/// Persist MemDb accounts + storage to disk.
pub fn persist_evm_accounts(dir: impl AsRef<Path>, db: &MemDb) -> io::Result<()> {
    let dir = dir.as_ref();
    fs::create_dir_all(dir)?;

    let mut accounts: Vec<PersistedAccount> = db
        .accounts
        .iter()
        .map(|(addr, info)| {
            let storage: Vec<(String, String)> = db
                .storage
                .iter()
                .filter(|((a, _), _)| a == addr)
                .filter(|(_, v)| **v != U256::ZERO)
                .map(|((_, slot), val)| {
                    let s: [u8; 32] = slot.to_be_bytes();
                    let v: [u8; 32] = val.to_be_bytes();
                    (hex::encode(s), hex::encode(v))
                })
                .collect();

            PersistedAccount {
                address: format!("0x{}", hex::encode(addr.as_slice())),
                nonce: info.nonce,
                balance: info.balance.to_string(),
                code_hash: format!("0x{}", hex::encode(info.code_hash.0)),
                storage,
            }
        })
        .collect();

    accounts.sort_by(|a, b| a.address.cmp(&b.address));

    let data = serde_json::to_string_pretty(&accounts)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;
    fs::write(accounts_path(dir), data)?;
    Ok(())
}

/// Load EVM accounts from disk back into a MemDb.
pub fn load_evm_accounts(dir: impl AsRef<Path>, db: &mut MemDb) -> io::Result<()> {
    let p = accounts_path(dir.as_ref());
    if !p.exists() {
        return Ok(());
    }

    let data = fs::read_to_string(&p)?;
    let accounts: Vec<PersistedAccount> = serde_json::from_str(&data)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;

    for acc in accounts {
        let addr_bytes = hex::decode(acc.address.trim_start_matches("0x")).unwrap_or_default();
        if addr_bytes.len() != 20 {
            continue;
        }
        let mut a = [0u8; 20];
        a.copy_from_slice(&addr_bytes);
        let addr = Address::from(a);

        let balance = acc.balance.parse::<U256>().unwrap_or(U256::ZERO);

        let code_hash_bytes =
            hex::decode(acc.code_hash.trim_start_matches("0x")).unwrap_or_else(|_| vec![0u8; 32]);
        let mut ch = [0u8; 32];
        let len = code_hash_bytes.len().min(32);
        ch[..len].copy_from_slice(&code_hash_bytes[..len]);
        let code_hash = B256::from(ch);

        let info = AccountInfo {
            nonce: acc.nonce,
            balance,
            code_hash,
            code: None, // code reloaded lazily from db.code map
        };
        db.accounts.insert(addr, info);

        for (slot_hex, val_hex) in acc.storage {
            let s_bytes = hex::decode(&slot_hex).unwrap_or_default();
            let v_bytes = hex::decode(&val_hex).unwrap_or_default();
            if s_bytes.len() != 32 || v_bytes.len() != 32 {
                continue;
            }
            let mut sb = [0u8; 32];
            sb.copy_from_slice(&s_bytes);
            let mut vb = [0u8; 32];
            vb.copy_from_slice(&v_bytes);
            let slot = U256::from_be_bytes(sb);
            let val = U256::from_be_bytes(vb);
            db.storage.insert((addr, slot), val);
        }
    }

    tracing::info!(
        accounts = db.accounts.len(),
        "EVM accounts loaded from disk"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn snapshot_roundtrip() {
        let dir = TempDir::new().unwrap();
        let snap = StateSnapshot {
            schema_version: 1,
            chain_id: 9999,
            block_number: 42,
            base_fee: 1_000_000_000,
            blocks: vec![],
            receipts: vec![],
            txs: Default::default(),
            receipts_by_block: Default::default(),
            pending_withdrawals: vec![],
            txpool: TxPool::default(),
        };
        save_snapshot(dir.path(), &snap).unwrap();
        let loaded = load_snapshot(dir.path()).unwrap().unwrap();
        assert_eq!(loaded.block_number, 42);
        assert_eq!(loaded.chain_id, 9999);
    }

    #[test]
    fn load_snapshot_missing_returns_none() {
        let dir = TempDir::new().unwrap();
        let result = load_snapshot(dir.path()).unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn head_roundtrip() {
        let dir = TempDir::new().unwrap();
        save_head(dir.path(), 100, "0xabc").unwrap();
        let head = load_head(dir.path()).unwrap().unwrap();
        assert_eq!(head.block_number, 100);
        assert_eq!(head.block_hash, "0xabc");
    }
}
