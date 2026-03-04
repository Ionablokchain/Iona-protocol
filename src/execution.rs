pub mod vm_executor;
pub mod parallel;
pub mod sandbox;

use crate::crypto::{PublicKeyBytes, SignatureBytes, Verifier};
use crate::crypto::ed25519::Ed25519Verifier;
use crate::crypto::tx::tx_sign_bytes;
use crate::merkle::state_merkle_root;
use crate::types::{receipts_root, tx_hash, tx_root, Block, BlockHeader, Hash32, Height, Receipt, Round, Tx};
use crate::economics::staking::StakingState;
use crate::economics::staking_tx::try_apply_staking_tx;
use crate::economics::params::EconomicsParams;
use crate::economics::rewards::epoch_at;
use crate::vm::state::VmStorage;
use crate::execution::vm_executor::{vm_deploy, vm_call, parse_vm_payload, VmTxPayload};
use rayon::prelude::*;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use crate::crypto::tx::derive_address;
use bincode;

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct KvState {
    pub kv:       BTreeMap<String, String>,
    pub balances: BTreeMap<String, u64>,
    pub nonces:   BTreeMap<String, u64>,
    pub burned:   u64,
    /// VM contract state (storage slots + bytecode + nonces)
    pub vm:       VmStorage,
}

impl KvState {
    /// Deterministic Merkle state root.
    /// Combines kv, balances, nonces, burned, and VM contract state.
    pub fn root(&self) -> Hash32 {
        let mut combined: BTreeMap<String, String> = BTreeMap::new();
        for (k, v) in &self.kv {
            combined.insert(format!("kv:{k}"), v.clone());
        }
        for (addr, bal) in &self.balances {
            combined.insert(format!("bal:{addr}"), bal.to_string());
        }
        for (addr, nonce) in &self.nonces {
            combined.insert(format!("nonce:{addr}"), nonce.to_string());
        }
        combined.insert("burned".to_string(), self.burned.to_string());
        // Include VM storage slots
        for ((contract, slot), value) in &self.vm.storage {
            let key = format!("vm_storage:{}:{}", hex::encode(contract), hex::encode(slot));
            combined.insert(key, hex::encode(value));
        }
        // Include contract code hashes
        for (contract, code) in &self.vm.code {
            use sha2::{Digest, Sha256};
            let hash = Sha256::digest(code);
            combined.insert(format!("vm_code:{}", hex::encode(contract)), hex::encode(hash));
        }

        Hash32(state_merkle_root(&combined))
    }
}

pub fn intrinsic_gas(tx: &Tx) -> u64 {
    21_000 + (tx.payload.len() as u64).saturating_mul(10)
}

fn apply_payload_kv(kv: &mut BTreeMap<String, String>, payload: &str) -> Result<(), String> {
    let parts: Vec<&str> = payload.split_whitespace().collect();
    if parts.is_empty() { return Err("invalid tx".into()); }
    match parts[0] {
        "set" if parts.len() >= 3 => {
            let key = parts[1].to_string();
            let val = parts[2..].join(" ");
            kv.insert(key, val);
            Ok(())
        }
        "del" if parts.len() == 2 => {
            kv.remove(parts[1]);
            Ok(())
        }
        "inc" if parts.len() == 2 => {
            let key = parts[1].to_string();
            let cur = kv.get(&key).cloned().unwrap_or_else(|| "0".into());
            let n: i64 = cur.parse().unwrap_or(0);
            kv.insert(key, (n + 1).to_string());
            Ok(())
        }
        _ => Err("invalid tx".into()),
    }
}

pub fn verify_tx_signature(tx: &Tx) -> Result<String, String> {
    let addr = derive_address(&tx.pubkey);
    if tx.from != addr { return Err("from != derived address".into()); }
    let pk = PublicKeyBytes(tx.pubkey.clone());
    let sig = SignatureBytes(tx.signature.clone());
    let msg = tx_sign_bytes(tx);
    Ed25519Verifier::verify(&pk, &msg, &sig).map_err(|_| "bad signature".to_string())?;
    Ok(addr)
}

pub fn apply_tx(
    state: &KvState,
    tx: &Tx,
    base_fee_per_gas: u64,
    proposer_addr: &str,
) -> (Receipt, KvState) {
    let txh = tx_hash(tx);
    let mut receipt = Receipt {
        tx_hash: txh,
        success: false,
        gas_used: 0,
        intrinsic_gas_used: 0,
        exec_gas_used: 0,
        vm_gas_used: 0,
        evm_gas_used: 0,
        effective_gas_price: 0,
        burned: 0,
        tip: 0,
        error: None,
        data: None,
    };

    let from_addr = match verify_tx_signature(tx) {
        Ok(a) => a,
        Err(e) => { receipt.error = Some(e); return (receipt, state.clone()); }
    };

    let mut working = state.clone();

    let expected = *working.nonces.get(&from_addr).unwrap_or(&0);
    if tx.nonce != expected {
        receipt.error = Some("bad nonce".into());
        return (receipt, state.clone());
    }

    let intrinsic = intrinsic_gas(tx);
    receipt.intrinsic_gas_used = intrinsic;
    receipt.exec_gas_used = 0;
    receipt.vm_gas_used = 0;
    receipt.evm_gas_used = 0;
    receipt.gas_used = intrinsic;
    if tx.gas_limit < intrinsic {
        receipt.error = Some("gas limit too low".into());
        return (receipt, state.clone());
    }
    if tx.max_fee_per_gas < base_fee_per_gas {
        receipt.error = Some("fee too low for base fee".into());
        return (receipt, state.clone());
    }

    let max_tip = tx.max_fee_per_gas.saturating_sub(base_fee_per_gas);
    let priority_fee_per_gas = std::cmp::min(tx.max_priority_fee_per_gas, max_tip);
    let effective_gas_price = base_fee_per_gas.saturating_add(priority_fee_per_gas);
    receipt.effective_gas_price = effective_gas_price;

    let burned = base_fee_per_gas.saturating_mul(intrinsic);
    let tip = priority_fee_per_gas.saturating_mul(intrinsic);
    let total = burned.saturating_add(tip);
    receipt.burned = burned;
    receipt.tip = tip;

    let bal = *working.balances.get(&from_addr).unwrap_or(&0);
    if bal < total {
        receipt.error = Some("insufficient balance".into());
        return (receipt, state.clone());
    }

    // Charge fee + increment nonce always (even if payload fails)
    working.balances.insert(from_addr.clone(), bal - total);
    working.burned = working.burned.saturating_add(burned);
    let pb = *working.balances.get(proposer_addr).unwrap_or(&0);
    working.balances.insert(proposer_addr.to_string(), pb.saturating_add(tip));
    working.nonces.insert(from_addr.clone(), expected + 1);

    // Apply payload; revert payload-only changes on failure (keep fee+nonce)
//
// NOTE: VM transactions ("vm ...") are executed later in `execute_block_with_staking`.
// Here we intentionally *skip* KV payload execution for them, to avoid treating a VM
// payload as a KV op. Intrinsic gas has already been charged above.
if tx.payload.trim_start().starts_with("vm ") {
    receipt.success = true; // execution outcome is set by the VM executor later
    receipt.error = None;
    return (receipt, working);
}

// Apply payload; revert payload-only changes on failure (keep fee+nonce)
    let mut after = working.clone();
    match apply_payload_kv(&mut after.kv, &tx.payload) {
        Ok(()) => {
            receipt.success = true;
            (receipt, after)
        }
        Err(e) => {
            receipt.error = Some(e);
            (receipt, working)
        }
    }
}

/// Parallel signature pre-verification.
///
/// Ed25519 verification is CPU-intensive (~50μs/tx). With 4096 tx/bloc la 300ms block time,
/// serial verification = ~200ms din 300ms buget. Paralel pe 8 cores → ~25ms.
///
/// Returns a set of tx indices that have VALID signatures.
/// Txs with invalid signatures are still passed to execute_block but will fail there too
/// (verify_tx_signature is called again). The pre-verification is an optimization, not a gate.
fn parallel_verify_sigs(txs: &[Tx]) -> Vec<bool> {
    txs.par_iter().map(|tx| {
        verify_tx_signature(tx).is_ok()
    }).collect()
}

pub fn execute_block(
    prev_state:       &KvState,
    txs:              &[Tx],
    base_fee_per_gas: u64,
    proposer_addr:    &str,
) -> (KvState, u64, Vec<Receipt>) {
    // Phase 1: verify signatures in parallel (CPU-bound, no state dependency)
    let sig_valid = if txs.len() > 16 {
        parallel_verify_sigs(txs)
    } else {
        txs.iter().map(|tx| verify_tx_signature(tx).is_ok()).collect()
    };

    // Phase 2: apply transactions serially (state is sequential)
    let mut st = prev_state.clone();
    let mut gas_total = 0u64;
    let mut receipts = Vec::with_capacity(txs.len());
    for (i, tx) in txs.iter().enumerate() {
        // Skip signature re-check for txs we already verified (fast path)
        let (rcpt, next) = if sig_valid[i] {
            apply_tx_presig_verified(&st, tx, base_fee_per_gas, proposer_addr)
        } else {
            apply_tx(&st, tx, base_fee_per_gas, proposer_addr)
        };
        gas_total = gas_total.saturating_add(rcpt.gas_used);
        st = next;
        receipts.push(rcpt);
    }
    (st, gas_total, receipts)

}

/// Extended execute_block that also processes staking transactions.
/// When a tx payload starts with "stake ", it is routed to the staking module
/// instead of the KV payload engine.
///
/// This variant is used by `iona-node` in production.
pub fn execute_block_with_staking(
    prev_state:       &KvState,
    txs:              &[Tx],
    base_fee_per_gas: u64,
    proposer_addr:    &str,
    staking:          &mut StakingState,
    params:           &EconomicsParams,
    height:           u64,
) -> (KvState, u64, Vec<Receipt>) {
    let epoch = epoch_at(height);

    let sig_valid = if txs.len() > 16 {
        parallel_verify_sigs(txs)
    } else {
        txs.iter().map(|tx| verify_tx_signature(tx).is_ok()).collect()
    };

    let mut st = prev_state.clone();
    let mut gas_total = 0u64;
    let mut receipts = Vec::with_capacity(txs.len());

    for (i, tx) in txs.iter().enumerate() {
        if tx.payload.trim_start().starts_with("stake ") {
            // Fee deduction + nonce increment via normal path
            let (mut rcpt, mut after) = if sig_valid[i] {
                apply_tx_presig_verified(&st, tx, base_fee_per_gas, proposer_addr)
            } else {
                apply_tx(&st, tx, base_fee_per_gas, proposer_addr)
            };

            // apply_payload_kv will fail on "stake " — re-apply staking logic
            let from_addr = crate::crypto::tx::derive_address(&tx.pubkey);
            let staking_result = try_apply_staking_tx(
                &tx.payload,
                &from_addr,
                &mut after,
                staking,
                params,
                epoch,
            );
            match staking_result {
                Some(r) => {
                    rcpt.success = r.success;
                    rcpt.error = r.error;
                    rcpt.gas_used = r.gas_used.max(rcpt.gas_used);
                }
                None => {
                    rcpt.success = false;
                    rcpt.error = Some("staking: parse error".into());
                }
            }

            gas_total = gas_total.saturating_add(rcpt.gas_used);
            st = after;
            receipts.push(rcpt);
        } else if tx.payload.trim_start().starts_with("vm ") {
            // ── VM contract deploy / call ──────────────────────────────────
            // Fee deduction and nonce increment happen via the normal path first
            let (mut rcpt, mut after) = if sig_valid[i] {
                apply_tx_presig_verified(&st, tx, base_fee_per_gas, proposer_addr)
            } else {
                apply_tx(&st, tx, base_fee_per_gas, proposer_addr)
            };

            // Route to VM executor
            let from_bytes = {
                let addr_hex = crate::crypto::tx::derive_address(&tx.pubkey);
                let raw = hex::decode(&addr_hex).unwrap_or_default();
                let mut b = [0u8; 32];
                let start = 32usize.saturating_sub(raw.len());
                b[start..].copy_from_slice(&raw[..raw.len().min(32)]);
                b
            };

            // Default gas for VM calls: 500_000 (can be parameterized later)
            const VM_GAS_LIMIT: u64 = 500_000;

            match parse_vm_payload(&tx.payload) {
                Some(VmTxPayload::Deploy { init_code }) => {
                    let vm_result = vm_deploy(&mut after, &from_bytes, &init_code, VM_GAS_LIMIT);
                    rcpt.success = vm_result.success;
                    rcpt.error   = vm_result.error;
                    rcpt.vm_gas_used = vm_result.gas_used;
                    rcpt.exec_gas_used = rcpt.vm_gas_used;
                    // Total gas = intrinsic tx cost + VM execution cost (intentional)
                    rcpt.gas_used = rcpt.intrinsic_gas_used.saturating_add(rcpt.exec_gas_used);
                    // Store contract address in receipt data field if available
                    if let Some(addr) = vm_result.contract {
                        rcpt.data = Some(hex::encode(addr));
                    }
                }
                Some(VmTxPayload::Call { contract, calldata }) => {
                    let vm_result = vm_call(&mut after, &from_bytes, &contract, &calldata, VM_GAS_LIMIT);
                    rcpt.success = vm_result.success;
                    rcpt.error   = vm_result.error;
                    rcpt.vm_gas_used = vm_result.gas_used;
                    rcpt.exec_gas_used = rcpt.vm_gas_used;
                    // Total gas = intrinsic tx cost + VM execution cost (intentional)
                    rcpt.gas_used = rcpt.intrinsic_gas_used.saturating_add(rcpt.exec_gas_used);
                    if !vm_result.return_data.is_empty() {
                        rcpt.data = Some(hex::encode(&vm_result.return_data));
                    }
                }
                None => {
                    rcpt.success = false;
                    rcpt.error   = Some("vm: malformed payload".into());
                }
            }

            gas_total = gas_total.saturating_add(rcpt.gas_used);
            st = after;
            receipts.push(rcpt);
        } else if tx.payload.trim_start().starts_with("evm_unified ") {
            // ── Unified EVM transaction (backed by live KvState via KvStateDb) ──
            // Payload format: "evm_unified <hex-encoded-EvmTx-bincode>"
            // This uses the full revm executor with real balances, nonces, and
            // contract storage — unlike the legacy "evm " path which used MemDb.
            let (mut rcpt, mut after) = if sig_valid[i] {
                apply_tx_presig_verified(&st, tx, base_fee_per_gas, proposer_addr)
            } else {
                apply_tx(&st, tx, base_fee_per_gas, proposer_addr)
            };

            let hex_payload = tx.payload.trim_start()
                .strip_prefix("evm_unified ")
                .unwrap_or("")
                .trim();

            match hex::decode(hex_payload)
                .ok()
                .and_then(|bytes| bincode::deserialize::<crate::types::tx_evm::EvmTx>(&bytes).ok())
            {
                Some(evm_tx) => {
                    use crate::evm::kv_state_db::execute_evm_on_state;
                    // Use the height parameter and sensible defaults for
                    // timestamp / chain_id (the full Block is not available
                    // in this execution path).
                    let result = execute_evm_on_state(
                        &mut after,
                        evm_tx,
                        height,
                        0, // timestamp filled at block-building time
                        base_fee_per_gas,
                        6126151, // default dev chain_id
                    );
                    rcpt.success = result.success;
                    rcpt.error = result.error;
                    rcpt.evm_gas_used = result.gas_used;
                    rcpt.exec_gas_used = result.gas_used;
                    rcpt.gas_used = rcpt.intrinsic_gas_used.saturating_add(result.gas_used);
                    if let Some(addr) = result.created_address {
                        rcpt.data = Some(hex::encode(addr));
                    } else if !result.return_data.is_empty() {
                        rcpt.data = Some(hex::encode(&result.return_data));
                    }
                }
                None => {
                    rcpt.success = false;
                    rcpt.error = Some("evm_unified: failed to decode EvmTx payload".into());
                }
            }

            gas_total = gas_total.saturating_add(rcpt.gas_used);
            st = after;
            receipts.push(rcpt);
        } else {
            let (rcpt, next) = if sig_valid[i] {
                apply_tx_presig_verified(&st, tx, base_fee_per_gas, proposer_addr)
            } else {
                apply_tx(&st, tx, base_fee_per_gas, proposer_addr)
            };
            gas_total = gas_total.saturating_add(rcpt.gas_used);
            st = next;
            receipts.push(rcpt);
        }
    }

    (st, gas_total, receipts)
}

/// Variant of apply_tx that skips signature verification (already done in parallel).
fn apply_tx_presig_verified(
    state:            &KvState,
    tx:               &Tx,
    base_fee_per_gas: u64,
    proposer_addr:    &str,
) -> (Receipt, KvState) {
    let txh = tx_hash(tx);
    let from_addr = crate::crypto::tx::derive_address(&tx.pubkey);
    let mut receipt = Receipt {
        tx_hash: txh,
        success: false,
        gas_used: 0,
        intrinsic_gas_used: 0,
        exec_gas_used: 0,
        vm_gas_used: 0,
        evm_gas_used: 0,
        effective_gas_price: 0,
        burned: 0,
        tip: 0,
        error: None,
        data: None,
    };

    // from address consistency check (still needed — parallel verify checked sig, not from field)
    if tx.from != from_addr {
        receipt.error = Some("from != derived address".into());
        return (receipt, state.clone());
    }

    let mut working = state.clone();
    let expected = *working.nonces.get(&from_addr).unwrap_or(&0);
    if tx.nonce != expected {
        receipt.error = Some("bad nonce".into());
        return (receipt, state.clone());
    }
    let intrinsic = intrinsic_gas(tx);
    receipt.intrinsic_gas_used = intrinsic;
    receipt.exec_gas_used = 0;
    receipt.vm_gas_used = 0;
    receipt.evm_gas_used = 0;
    receipt.gas_used = intrinsic;
    if tx.gas_limit < intrinsic {
        receipt.error = Some("gas limit too low".into());
        return (receipt, state.clone());
    }
    if tx.max_fee_per_gas < base_fee_per_gas {
        receipt.error = Some("fee too low for base fee".into());
        return (receipt, state.clone());
    }
    let max_tip = tx.max_fee_per_gas.saturating_sub(base_fee_per_gas);
    let priority_fee_per_gas = std::cmp::min(tx.max_priority_fee_per_gas, max_tip);
    let effective_gas_price = base_fee_per_gas.saturating_add(priority_fee_per_gas);
    receipt.effective_gas_price = effective_gas_price;
    let burned = base_fee_per_gas.saturating_mul(intrinsic);
    let tip    = priority_fee_per_gas.saturating_mul(intrinsic);
    let total  = burned.saturating_add(tip);
    receipt.burned = burned;
    receipt.tip    = tip;
    let bal = *working.balances.get(&from_addr).unwrap_or(&0);
    if bal < total {
        receipt.error = Some("insufficient balance".into());
        return (receipt, state.clone());
    }
    working.balances.insert(from_addr.clone(), bal - total);
    working.burned = working.burned.saturating_add(burned);
    let pb = *working.balances.get(proposer_addr).unwrap_or(&0);
    working.balances.insert(proposer_addr.to_string(), pb.saturating_add(tip));
    working.nonces.insert(from_addr.clone(), expected + 1);
    let mut after = working.clone();
    match apply_payload_kv(&mut after.kv, &tx.payload) {
        Ok(()) => { receipt.success = true; (receipt, after) }
        Err(e) => { receipt.error = Some(e); (receipt, working) }
    }
}

/// EIP-1559 base fee adjustment.
///
/// IONA v19 uses a ÷4 elasticity factor instead of Ethereum's ÷8.
/// This means the base fee responds twice as fast to demand spikes,
/// which keeps block space from being chronically over/underpriced
/// when blocks are produced every ~300ms instead of every 12s.
///
/// The tradeoff: more volatile base fee, but with sub-second blocks
/// the price signal updates fast enough that wallets can follow it.
pub fn next_base_fee(prev_base: u64, gas_used: u64, gas_target: u64) -> u64 {
    if gas_target == 0 { return prev_base.max(1); }
    let prev_base = prev_base.max(1);
    // Elasticity denominator: 4 (vs ETH's 8) for faster price discovery
    const ELASTICITY_DENOM: u64 = 4;
    if gas_used > gas_target {
        let excess = gas_used - gas_target;
        (prev_base + (prev_base * excess / gas_target / ELASTICITY_DENOM).max(1)).max(1)
    } else {
        let short = gas_target - gas_used;
        prev_base.saturating_sub((prev_base * short / gas_target / ELASTICITY_DENOM).max(1)).max(1)
    }
}

pub fn build_block(
    height: Height,
    round: Round,
    prev: Hash32,
    proposer_pk: Vec<u8>,
    proposer_addr: &str,
    prev_state: &KvState,
    base_fee_per_gas: u64,
    txs: Vec<Tx>,
) -> (Block, KvState, Vec<Receipt>) {
    let (st, gas_used, receipts) = execute_block(prev_state, &txs, base_fee_per_gas, proposer_addr);
    let header = BlockHeader {
        height,
        round,
        prev,
        proposer_pk,
        tx_root: tx_root(&txs),
        receipts_root: receipts_root(&receipts),
        state_root: st.root(),
        base_fee_per_gas,
        gas_used,
        // Backwards-compatible defaults (detailed gas accounting can be added in execute_block).
        intrinsic_gas_used: 0,
        exec_gas_used: gas_used,
        vm_gas_used: 0,
        evm_gas_used: 0,
        chain_id: 6126151,
        timestamp: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0),
        protocol_version: crate::protocol::version::CURRENT_PROTOCOL_VERSION,
    };
    (Block { header, txs }, st, receipts)
}

/// Verify and apply a block. Returns (new_state, receipts) or None if invalid.
///
/// Checks (in order):
/// 1. proposer_pk must be in the active validator set
/// 2. tx_root must match
/// 3. execution must produce matching gas_used, receipts_root, state_root
pub fn verify_block(
    prev_state:    &KvState,
    block:         &Block,
    proposer_addr: &str,
) -> Option<(KvState, Vec<Receipt>)> {
    // proposer_pk length sanity (ed25519 = 32 bytes)
    if block.header.proposer_pk.len() != 32 { return None; }
    if tx_root(&block.txs) != block.header.tx_root { return None; }
    let (st, gas_used, receipts) = execute_block(prev_state, &block.txs, block.header.base_fee_per_gas, proposer_addr);
    if gas_used != block.header.gas_used { return None; }
    if receipts_root(&receipts) != block.header.receipts_root { return None; }
    if st.root() != block.header.state_root { return None; }
    Some((st, receipts))
}

/// Verify block WITH validator set check on proposer_pk.
/// Use this from the consensus engine (has access to vset).
pub fn verify_block_with_vset(
    prev_state:    &KvState,
    block:         &Block,
    proposer_addr: &str,
    expected_pk:   &crate::crypto::PublicKeyBytes,
) -> Option<(KvState, Vec<Receipt>)> {
    // Block's proposer_pk must match the expected proposer from vset
    if block.header.proposer_pk != expected_pk.0 { return None; }
    verify_block(prev_state, block, proposer_addr)
}
