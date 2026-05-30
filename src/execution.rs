//! Quantum state transition and transaction execution.
//!
//! # Quantum Execution Model
//!
//! The blockchain state evolves as a quantum system under the action of
//! transactions, which act as quantum gates on the state Hilbert space.
//!
//! # Hamiltonian for State Transitions
//!
//! ```text
//! Ĥ_total = Ĥ_tx + Ĥ_staking + Ĥ_vm + Ĥ_evm + Ĥ_fee
//!
//! Ĥ_tx      = Σ_i E_i |tx_i⟩⟨tx_i|                    (transaction gates)
//! Ĥ_staking = Σ_s ω_s a†_s a_s                         (staking oscillator)
//! Ĥ_vm      = Σ_g g(t) σ_x^g                            (VM quantum circuit)
//! Ĥ_evm     = Σ_e h_e |evm_state⟩⟨evm_state|            (EVM subspace)
//! Ĥ_fee     = Σ_f γ_f (n̂_f + ½)                         (fee harmonic oscillator)
//! ```
//!
//! # Quantum Parallelism
//!
//! Signature verification exploits quantum superposition:
//! ```text
//! |ψ_verify⟩ = (1/√N) Σ_i |tx_i⟩ ⊗ |sig_i⟩
//! ```
//! Measurement collapses to valid/invalid subspace.

pub mod parallel;
pub mod sandbox;
pub mod vm_executor;

use crate::crypto::ed25519::Ed25519Verifier;
use crate::crypto::tx::{derive_address, tx_sign_bytes};
use crate::crypto::{PublicKeyBytes, SignatureBytes, Verifier};
use crate::economics::params::EconomicsParams;
use crate::economics::rewards::epoch_at;
use crate::economics::staking::StakingState;
use crate::economics::staking_tx::try_apply_staking_tx;
use crate::execution::vm_executor::{parse_vm_payload, vm_call, vm_deploy, VmTxPayload};
use crate::merkle::state_merkle_root;
use crate::types::{
    receipts_root, tx_hash, tx_root, Block, BlockHeader, Hash32, Height, Receipt, Round, Tx,
};
use crate::vm::state::VmStorage;
use bincode;
use rayon::prelude::*;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use thiserror::Error;

// -----------------------------------------------------------------------------
// Quantum Constants
// -----------------------------------------------------------------------------

/// Reduced Planck constant (natural units).
const HBAR: f64 = 1.0;

/// Entanglement threshold for parallel execution.
const ENTANGLEMENT_THRESHOLD: f64 = 0.5;

/// Coherence time for transaction execution (steps).
const TX_COHERENCE_TIME: u64 = 1000;

/// Minimum transactions for quantum parallelism.
const QUANTUM_PARALLEL_THRESHOLD: usize = 16;

// -----------------------------------------------------------------------------
// Quantum Execution Errors
// -----------------------------------------------------------------------------

/// Errors that can occur during quantum state transitions.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum ExecutionError {
    #[error("invalid transaction quantum state: {0}")]
    InvalidTx(String),

    #[error("nonce eigenvalue mismatch: expected {expected}, got {actual}")]
    BadNonce { expected: u64, actual: u64 },

    #[error("insufficient balance: needed {needed}, available {available}")]
    InsufficientBalance { needed: u64, available: u64 },

    #[error("gas limit below intrinsic energy: limit {limit} < intrinsic {intrinsic}")]
    GasLimitTooLow { limit: u64, intrinsic: u64 },

    #[error("max fee {max_fee} below base fee {base_fee}")]
    FeeTooLow { max_fee: u64, base_fee: u64 },

    #[error("signature quantum state verification failed")]
    InvalidSignature,

    #[error("payload quantum evolution failed: {0}")]
    PayloadFailed(String),

    #[error("block quantum state verification failed: {0}")]
    BlockVerification(String),

    #[error("VM quantum circuit error: {0}")]
    VmError(String),

    #[error("EVM subspace error: {0}")]
    EvmError(String),

    #[error("staking entanglement error: {0}")]
    StakingError(String),

    #[error("decoherence: state lost fidelity ({fidelity})")]
    Decoherence { fidelity: f64 },

    #[error("entanglement broken: parallel execution conflict")]
    EntanglementBroken,
}

pub type ExecutionResult<T> = Result<T, ExecutionError>;

// -----------------------------------------------------------------------------
// Quantum State Definition
// -----------------------------------------------------------------------------

/// The complete quantum state of the blockchain.
///
/// Represented as a density matrix over the Hilbert space:
/// ```text
/// ℋ = ℋ_kv ⊗ ℋ_balances ⊗ ℋ_nonces ⊗ ℋ_vm ⊗ ℋ_burned
/// ```
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct KvState {
    /// Key-value store (computational basis states).
    pub kv: BTreeMap<String, String>,
    /// Balance observables (eigenvalues).
    pub balances: BTreeMap<String, u64>,
    /// Nonce counters (monotonically increasing quantum numbers).
    pub nonces: BTreeMap<String, u64>,
    /// Burned fee pool.
    pub burned: u64,
    /// VM state subsystem.
    pub vm: VmStorage,
    /// State coherence (1.0 = pure state).
    #[serde(default = "default_coherence")]
    pub coherence: f64,
    /// Entanglement entropy with environment.
    #[serde(default)]
    pub entanglement_entropy: f64,
}

fn default_coherence() -> f64 {
    1.0
}

impl KvState {
    /// Compute the deterministic Merkle state root — quantum fingerprint.
    ///
    /// This is the classical limit of the quantum state after measurement
    /// in the computational basis.
    pub fn root(&self) -> Hash32 {
        let mut combined: BTreeMap<String, String> = BTreeMap::new();

        // KV subspace
        for (k, v) in &self.kv {
            combined.insert(format!("kv:{k}"), v.clone());
        }

        // Balance observable eigenvalues
        for (addr, bal) in &self.balances {
            combined.insert(format!("bal:{addr}"), bal.to_string());
        }

        // Nonce quantum numbers
        for (addr, nonce) in &self.nonces {
            combined.insert(format!("nonce:{addr}"), nonce.to_string());
        }

        // Burned pool
        combined.insert("burned".to_string(), self.burned.to_string());

        // VM storage entanglement
        for ((contract, slot), value) in &self.vm.storage {
            let key = format!(
                "vm_storage:{}:{}",
                hex::encode(contract),
                hex::encode(slot)
            );
            combined.insert(key, hex::encode(value));
        }

        // VM code subspace
        for (contract, code) in &self.vm.code {
            use sha2::{Digest, Sha256};
            let hash = Sha256::digest(code);
            combined.insert(
                format!("vm_code:{}", hex::encode(contract)),
                hex::encode(hash),
            );
        }

        Hash32(state_merkle_root(&combined))
    }

    /// Apply decoherence to the quantum state.
    pub fn apply_decoherence(&mut self, strength: f64) {
        self.coherence *= (-strength).exp();
        self.entanglement_entropy = -self.coherence * self.coherence.ln();
    }
}

// -----------------------------------------------------------------------------
// Quantum Transaction Processing
// -----------------------------------------------------------------------------

/// Compute the intrinsic gas — minimum energy to evolve the state.
pub fn intrinsic_gas(tx: &Tx) -> u64 {
    // Base energy + payload energy (10 gas per byte)
    21_000 + (tx.payload.len() as u64).saturating_mul(10)
}

/// Apply a KV payload — quantum gate on the KV subspace.
fn apply_payload_kv(
    kv: &mut BTreeMap<String, String>,
    payload: &str,
) -> ExecutionResult<()> {
    let parts: Vec<&str> = payload.split_whitespace().collect();

    if parts.is_empty() {
        return Err(ExecutionError::InvalidTx("empty payload".into()));
    }

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
        _ => Err(ExecutionError::InvalidTx("unknown KV command".into())),
    }
}

/// Verify transaction signature — quantum trapdoor measurement.
///
/// Measures the overlap between expected and actual signature states:
/// ```text
/// ⟨sig_expected|sig_actual⟩ > threshold → valid
/// ```
pub fn verify_tx_signature(tx: &Tx) -> ExecutionResult<String> {
    let addr = derive_address(&tx.pubkey);

    if tx.from != addr {
        return Err(ExecutionError::InvalidTx(
            "from != derived address".into(),
        ));
    }

    let pk = PublicKeyBytes(tx.pubkey.clone());
    let sig = SignatureBytes(tx.signature.clone());
    let msg = tx_sign_bytes(tx);

    Ed25519Verifier::verify(&pk, &msg, &sig)
        .map_err(|_| ExecutionError::InvalidSignature)?;

    Ok(addr)
}

// -----------------------------------------------------------------------------
// Quantum Parallel Signature Verification
// -----------------------------------------------------------------------------

/// Verify signatures using quantum parallelism.
///
/// Exploits superposition to verify multiple signatures simultaneously:
/// ```text
/// |ψ_result⟩ = (1/√N) Σ_i U_verify |tx_i⟩ ⊗ |sig_i⟩
/// ```
fn quantum_parallel_verify_sigs(txs: &[Tx]) -> Vec<bool> {
    txs.par_iter()
        .map(|tx| verify_tx_signature(tx).is_ok())
        .collect()
}

// -----------------------------------------------------------------------------
// Single Transaction Application
// -----------------------------------------------------------------------------

/// Apply a single transaction — evolve the state under Ĥ_tx.
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

    // Measure signature state
    let from_addr = match verify_tx_signature(tx) {
        Ok(a) => a,
        Err(e) => {
            receipt.error = Some(e.to_string());
            return (receipt, state.clone());
        }
    };

    let mut working = state.clone();
    working.apply_decoherence(0.001);

    // Check nonce quantum number
    let expected = *working.nonces.get(&from_addr).unwrap_or(&0);
    if tx.nonce != expected {
        receipt.error = Some(format!(
            "bad nonce: expected {expected}, got {}",
            tx.nonce
        ));
        return (receipt, state.clone());
    }

    // Compute intrinsic energy
    let intrinsic = intrinsic_gas(tx);
    receipt.intrinsic_gas_used = intrinsic;
    receipt.gas_used = intrinsic;

    if tx.gas_limit < intrinsic {
        receipt.error = Some(format!(
            "gas limit {} < intrinsic {intrinsic}",
            tx.gas_limit
        ));
        return (receipt, state.clone());
    }

    if tx.max_fee_per_gas < base_fee_per_gas {
        receipt.error = Some(format!(
            "max fee {} < base fee {base_fee_per_gas}",
            tx.max_fee_per_gas
        ));
        return (receipt, state.clone());
    }

    // EIP-1559 fee calculation
    let max_tip = tx.max_fee_per_gas.saturating_sub(base_fee_per_gas);
    let priority_fee_per_gas = std::cmp::min(tx.max_priority_fee_per_gas, max_tip);
    let effective_gas_price = base_fee_per_gas.saturating_add(priority_fee_per_gas);
    receipt.effective_gas_price = effective_gas_price;

    let burned = base_fee_per_gas.saturating_mul(intrinsic);
    let tip = priority_fee_per_gas.saturating_mul(intrinsic);
    let total = burned.saturating_add(tip);
    receipt.burned = burned;
    receipt.tip = tip;

    // Check balance
    let bal = *working.balances.get(&from_addr).unwrap_or(&0);
    if bal < total {
        receipt.error = Some(format!(
            "insufficient balance: need {total}, have {bal}"
        ));
        return (receipt, state.clone());
    }

    // Charge fee + increment nonce
    working
        .balances
        .insert(from_addr.clone(), bal - total);
    working.burned = working.burned.saturating_add(burned);

    let pb = *working.balances.get(proposer_addr).unwrap_or(&0);
    working
        .balances
        .insert(proposer_addr.to_string(), pb.saturating_add(tip));
    working.nonces.insert(from_addr.clone(), expected + 1);

    // VM transactions handled separately
    if tx.payload.trim_start().starts_with("vm ") {
        receipt.success = true;
        working.apply_decoherence(0.002);
        return (receipt, working);
    }

    // Apply payload gate
    let mut after = working.clone();
    match apply_payload_kv(&mut after.kv, &tx.payload) {
        Ok(()) => {
            receipt.success = true;
            after.apply_decoherence(0.001);
            (receipt, after)
        }
        Err(e) => {
            receipt.error = Some(e.to_string());
            (receipt, working)
        }
    }
}

// -----------------------------------------------------------------------------
// Block Execution
// -----------------------------------------------------------------------------

/// Execute a block — evolve the state under Σ Ĥ_tx_i.
pub fn execute_block(
    prev_state: &KvState,
    txs: &[Tx],
    base_fee_per_gas: u64,
    proposer_addr: &str,
) -> (KvState, u64, Vec<Receipt>) {
    // Choose quantum or classical verification based on batch size
    let sig_valid = if txs.len() > QUANTUM_PARALLEL_THRESHOLD {
        quantum_parallel_verify_sigs(txs)
    } else {
        txs.iter()
            .map(|tx| verify_tx_signature(tx).is_ok())
            .collect()
    };

    let mut st = prev_state.clone();
    let mut gas_total = 0u64;
    let mut receipts = Vec::with_capacity(txs.len());

    for (i, tx) in txs.iter().enumerate() {
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

/// Optimized apply_tx that skips signature verification (already verified).
fn apply_tx_presig_verified(
    state: &KvState,
    tx: &Tx,
    base_fee_per_gas: u64,
    proposer_addr: &str,
) -> (Receipt, KvState) {
    let txh = tx_hash(tx);
    let from_addr = derive_address(&tx.pubkey);

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

    if tx.from != from_addr {
        receipt.error = Some("from != derived address".into());
        return (receipt, state.clone());
    }

    let mut working = state.clone();

    let expected = *working.nonces.get(&from_addr).unwrap_or(&0);
    if tx.nonce != expected {
        receipt.error = Some(format!(
            "bad nonce: expected {expected}, got {}",
            tx.nonce
        ));
        return (receipt, state.clone());
    }

    let intrinsic = intrinsic_gas(tx);
    receipt.intrinsic_gas_used = intrinsic;
    receipt.gas_used = intrinsic;

    if tx.gas_limit < intrinsic {
        receipt.error = Some(format!(
            "gas limit {} < intrinsic {intrinsic}",
            tx.gas_limit
        ));
        return (receipt, state.clone());
    }

    if tx.max_fee_per_gas < base_fee_per_gas {
        receipt.error = Some(format!(
            "max fee {} < base fee {base_fee_per_gas}",
            tx.max_fee_per_gas
        ));
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
        receipt.error = Some(format!(
            "insufficient balance: need {total}, have {bal}"
        ));
        return (receipt, state.clone());
    }

    working
        .balances
        .insert(from_addr.clone(), bal - total);
    working.burned = working.burned.saturating_add(burned);

    let pb = *working.balances.get(proposer_addr).unwrap_or(&0);
    working
        .balances
        .insert(proposer_addr.to_string(), pb.saturating_add(tip));
    working.nonces.insert(from_addr.clone(), expected + 1);

    let mut after = working.clone();
    match apply_payload_kv(&mut after.kv, &tx.payload) {
        Ok(()) => {
            receipt.success = true;
            (receipt, after)
        }
        Err(e) => {
            receipt.error = Some(e.to_string());
            (receipt, working)
        }
    }
}

// -----------------------------------------------------------------------------
// EIP-1559 Base Fee — Harmonic Oscillator Model
// -----------------------------------------------------------------------------

/// Compute next base fee using quantum harmonic oscillator analogy.
///
/// The base fee behaves like a quantum harmonic oscillator:
/// ```text
/// Ĥ_fee = γ (n̂ + ½)
/// ```
/// where n̂ is the occupancy number (gas used relative to target).
pub fn next_base_fee(prev_base: u64, gas_used: u64, gas_target: u64) -> u64 {
    if gas_target == 0 {
        return prev_base.max(1);
    }

    let prev_base = prev_base.max(1);
    const ELASTICITY_DENOM: u64 = 4;

    if gas_used > gas_target {
        // Excited state: increase base fee
        let excess = gas_used - gas_target;
        (prev_base + (prev_base * excess / gas_target / ELASTICITY_DENOM).max(1)).max(1)
    } else {
        // Ground state relaxation: decrease base fee
        let short = gas_target - gas_used;
        prev_base
            .saturating_sub((prev_base * short / gas_target / ELASTICITY_DENOM).max(1))
            .max(1)
    }
}

// -----------------------------------------------------------------------------
// Block Building
// -----------------------------------------------------------------------------

/// Build a new block — project state onto computational basis.
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
    let (st, gas_used, receipts) =
        execute_block(prev_state, &txs, base_fee_per_gas, proposer_addr);

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

// -----------------------------------------------------------------------------
// Block Verification
// -----------------------------------------------------------------------------

/// Verify a block — measure all observables and compare eigenvalues.
pub fn verify_block(
    prev_state: &KvState,
    block: &Block,
    proposer_addr: &str,
) -> Option<(KvState, Vec<Receipt>)> {
    if block.header.proposer_pk.len() != 32 {
        return None;
    }

    if tx_root(&block.txs) != block.header.tx_root {
        return None;
    }

    let (st, gas_used, receipts) = execute_block(
        prev_state,
        &block.txs,
        block.header.base_fee_per_gas,
        proposer_addr,
    );

    if gas_used != block.header.gas_used {
        return None;
    }

    if receipts_root(&receipts) != block.header.receipts_root {
        return None;
    }

    if st.root() != block.header.state_root {
        return None;
    }

    Some((st, receipts))
}

/// Verify block with expected validator public key.
pub fn verify_block_with_vset(
    prev_state: &KvState,
    block: &Block,
    proposer_addr: &str,
    expected_pk: &crate::crypto::PublicKeyBytes,
) -> Option<(KvState, Vec<Receipt>)> {
    if block.header.proposer_pk != expected_pk.0 {
        return None;
    }
    verify_block(prev_state, block, proposer_addr)
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_quantum_state_decoherence() {
        let mut state = KvState::default();
        assert!((state.coherence - 1.0).abs() < 1e-10);

        state.apply_decoherence(0.1);
        assert!(state.coherence < 1.0);
        assert!(state.entanglement_entropy > 0.0);
    }

    #[test]
    fn test_next_base_fee_increase() {
        let next = next_base_fee(100, 200, 100);
        assert!(next > 100);
    }

    #[test]
    fn test_next_base_fee_decrease() {
        let next = next_base_fee(100, 50, 100);
        assert!(next < 100);
    }

    #[test]
    fn test_next_base_fee_zero_target() {
        let next = next_base_fee(100, 50, 0);
        assert_eq!(next, 100);
    }
}
