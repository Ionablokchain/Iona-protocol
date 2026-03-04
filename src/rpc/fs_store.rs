use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::rpc::eth_rpc::{Block, Receipt, TxRecord, EthRpcState};
use crate::rpc::txpool::TxPool;
use crate::rpc::withdrawals::Withdrawal;

/// Full node snapshot (scaffold persistence).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StateSnapshot {
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

fn snapshot_path(dir: &Path) -> PathBuf {
    dir.join("state_snapshot.json")
}

pub fn load_snapshot(dir: impl AsRef<Path>) -> io::Result<Option<StateSnapshot>> {
    let dir = dir.as_ref();
    let p = snapshot_path(dir);
    if !p.exists() {
        return Ok(None);
    }
    let data = fs::read_to_string(p)?;
    let snap: StateSnapshot = serde_json::from_str(&data)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;
    Ok(Some(snap))
}

pub fn save_snapshot(dir: impl AsRef<Path>, snap: &StateSnapshot) -> io::Result<()> {
    let dir = dir.as_ref();
    fs::create_dir_all(dir)?;
    let p = snapshot_path(dir);
    let data = serde_json::to_string_pretty(snap)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;
    fs::write(p, data)?;
    Ok(())
}

pub fn snapshot_from_state(st: &EthRpcState) -> StateSnapshot {
    StateSnapshot {
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
}

/// Best-effort throttled persistence.
pub fn maybe_persist(st: &EthRpcState) {
    let Some(dir) = st.persist_dir.as_ref() else { return; };
    let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs();
    let mut last = st.last_persist_secs.lock().unwrap();
    if now.saturating_sub(*last) < st.persist_interval_secs {
        return;
    }
    *last = now;
    drop(last);

    let snap = snapshot_from_state(st);
    let _ = save_snapshot(dir, &snap);
}
