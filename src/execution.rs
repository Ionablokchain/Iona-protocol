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
use std::fmt;
use std::sync::Arc;
use std::time::{Duration, Instant};
use thiserror::Error;
use tracing::{debug, error, info, trace, warn};

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

/// Default max gas per block.
const DEFAULT_MAX_GAS_PER_BLOCK: u64 = 30_000_000;

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

    #[error("transaction already executed: duplicate hash {hash}")]
    DuplicateTx { hash: String },

    #[error("gas overflow: exceeded block gas limit {limit}")]
    GasOverflow { limit: u64 },

    #[error("invalid proposer: {0}")]
    InvalidProposer(String),
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

    /// Create a deep clone for parallel execution isolation.
    pub fn fork(&self) -> Self {
        self.clone()
    }

    /// Merge another state into this one (for parallel execution).
    /// Assumes no overlapping modifications.
    pub fn merge(&mut self, other: &Self) -> ExecutionResult<()> {
        // Check for conflicts (overlapping keys, balances, nonces, etc.)
        for (k, v) in &other.kv {
            if let Some(existing) = self.kv.get(k) {
                if existing != v {
                    return Err(ExecutionError::EntanglementBroken);
                }
            }
        }
        for (addr, bal) in &other.balances {
            if let Some(existing) = self.balances.get(addr) {
                if existing != bal {
                    return Err(ExecutionError::EntanglementBroken);
                }
            }
        }
        for (addr, nonce) in &other.nonces {
            if let Some(existing) = self.nonces.get(addr) {
                if existing != nonce {
                    return Err(ExecutionError::EntanglementBroken);
                }
            }
        }
        // Merge VM storage and code (assuming disjoint contracts)
        for (key, val) in &other.vm.storage {
            if let Some(existing) = self.vm.storage.get(key) {
                if existing != val {
                    return Err(ExecutionError::EntanglementBroken);
                }
            }
        }
        for (contract, code) in &other.vm.code {
            if let Some(existing) = self.vm.code.get(contract) {
                if existing != code {
                    return Err(ExecutionError::EntanglementBroken);
                }
            }
        }

        // No conflicts: merge all.
        self.kv.extend(other.kv.clone());
        self.balances.extend(other.balances.clone());
        self.nonces.extend(other.nonces.clone());
        self.burned = self.burned.max(other.burned);
        self.vm.storage.extend(other.vm.storage.clone());
        self.vm.code.extend(other.vm.code.clone());
        self.coherence = (self.coherence + other.coherence) / 2.0;
        self.entanglement_entropy = (self.entanglement_entropy + other.entanglement_entropy) / 2.0;
        Ok(())
    }
}

// -----------------------------------------------------------------------------
// Intrinsic Gas
// -----------------------------------------------------------------------------

/// Compute the intrinsic gas — minimum energy to evolve the state.
pub fn intrinsic_gas(tx: &Tx) -> u64 {
    // Base energy + payload energy (10 gas per byte)
    21_000 + (tx.payload.len() as u64).saturating_mul(10)
}

// -----------------------------------------------------------------------------
// KV Payload Application
// -----------------------------------------------------------------------------

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

// -----------------------------------------------------------------------------
// Signature Verification
// -----------------------------------------------------------------------------

/// Verify transaction signature — quantum trapdoor measurement.
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
fn quantum_parallel_verify_sigs(txs: &[Tx]) -> Vec<Result<String, ExecutionError>> {
    txs.par_iter()
        .map(|tx| verify_tx_signature(tx))
        .collect()
}

// -----------------------------------------------------------------------------
// Transaction Executor
// -----------------------------------------------------------------------------

/// Main transaction executor with state management and atomicity.
pub struct TransactionExecutor {
    /// Current state (mutable)
    state: KvState,
    /// Economics parameters
    econ_params: EconomicsParams,
    /// Proposer address
    proposer: String,
    /// Max gas per block
    max_gas_per_block: u64,
    /// Base fee per gas
    base_fee: u64,
    /// Track executed transaction hashes to prevent duplicates in a block
    executed_hashes: std::collections::HashSet<Hash32>,
    /// Gas used so far
    gas_used: u64,
    /// Receipts collected
    receipts: Vec<Receipt>,
}

impl TransactionExecutor {
    /// Create a new executor from a state and configuration.
    pub fn new(
        state: KvState,
        proposer: impl Into<String>,
        base_fee_per_gas: u64,
        max_gas: u64,
        econ_params: EconomicsParams,
    ) -> Self {
        Self {
            state,
            econ_params,
            proposer: proposer.into(),
            max_gas_per_block: if max_gas == 0 { DEFAULT_MAX_GAS_PER_BLOCK } else { max_gas },
            base_fee: base_fee_per_gas,
            executed_hashes: std::collections::HashSet::new(),
            gas_used: 0,
            receipts: Vec::new(),
        }
    }

    /// Execute a single transaction and update the state atomically.
    /// Returns the receipt and the updated gas usage.
    pub fn execute_tx(&mut self, tx: &Tx) -> ExecutionResult<&Receipt> {
        // Check for duplicate
        let txh = tx_hash(tx);
        if !self.executed_hashes.insert(txh) {
            return Err(ExecutionError::DuplicateTx {
                hash: hex::encode(txh.as_bytes()),
            });
        }

        // Apply the transaction
        let (receipt, new_state) = apply_tx(
            &self.state,
            tx,
            self.base_fee,
            &self.proposer,
            &self.econ_params,
        );

        // Update gas used
        self.gas_used = self.gas_used.saturating_add(receipt.gas_used);
        if self.gas_used > self.max_gas_per_block {
            return Err(ExecutionError::GasOverflow {
                limit: self.max_gas_per_block,
            });
        }

        // Update state
        self.state = new_state;
        self.receipts.push(receipt);

        Ok(self.receipts.last().unwrap())
    }

    /// Execute a batch of transactions sequentially.
    pub fn execute_batch(&mut self, txs: &[Tx]) -> ExecutionResult<Vec<&Receipt>> {
        let mut results = Vec::with_capacity(txs.len());
        for tx in txs {
            let receipt = self.execute_tx(tx)?;
            results.push(receipt);
        }
        Ok(results)
    }

    /// Execute a batch of transactions in parallel using fork-join.
    ///
    /// This uses quantum parallelism for signature verification and execution
    /// when the batch is large enough. The state is forked for each transaction,
    /// executed in parallel, and then merged back.
    pub fn execute_batch_parallel(&mut self, txs: &[Tx]) -> ExecutionResult<Vec<&Receipt>> {
        if txs.len() <= QUANTUM_PARALLEL_THRESHOLD {
            return self.execute_batch(txs);
        }

        // Verify signatures in parallel
        let sig_results = quantum_parallel_verify_sigs(txs);
        let mut failed = Vec::new();
        for (i, result) in sig_results.iter().enumerate() {
            if result.is_err() {
                failed.push(i);
            }
        }
        if !failed.is_empty() {
            // For now, we just fail the whole batch if any signature is invalid.
            // In production, we might skip invalid transactions.
            return Err(ExecutionError::InvalidTx(format!(
                "{} transactions have invalid signatures",
                failed.len()
            )));
        }

        // Now execute in parallel using rayon
        // Since we already verified signatures, we can use a faster path.
        let base_state = &self.state;
        let base_fee = self.base_fee;
        let proposer = self.proposer.clone();
        let econ_params = self.econ_params.clone();

        // Execute each transaction on a fork
        let results: Vec<ExecutionResult<(Receipt, KvState)>> = txs
            .par_iter()
            .enumerate()
            .map(|(i, tx)| {
                // Skip if signature failed (should not happen, but safe)
                if sig_results[i].is_err() {
                    return Err(ExecutionError::InvalidSignature);
                }
                // Execute on a fork of the state (we will merge later)
                apply_tx(
                    base_state,
                    tx,
                    base_fee,
                    &proposer,
                    &econ_params,
                )
            })
            .collect();

        // Merge all results
        let mut final_state = self.state.clone();
        let mut all_receipts = Vec::with_capacity(txs.len());
        let mut total_gas = 0u64;

        for result in results {
            let (receipt, partial_state) = result?;
            // Merge partial state into final
            final_state.merge(&partial_state)?;
            all_receipts.push(receipt.clone());
            total_gas = total_gas.saturating_add(receipt.gas_used);
        }

        // Check gas limit
        if total_gas > self.max_gas_per_block {
            return Err(ExecutionError::GasOverflow {
                limit: self.max_gas_per_block,
            });
        }

        // Apply final state and update receipts
        self.state = final_state;
        self.gas_used = total_gas;
        self.receipts.extend(all_receipts);

        // Return references to the receipts
        Ok(self.receipts.iter().collect())
    }

    /// Finalize: compute the new state root and return the final state.
    pub fn finalize(self) -> (KvState, Vec<Receipt>, u64) {
        (self.state, self.receipts, self.gas_used)
    }

    /// Get current state.
    pub fn state(&self) -> &KvState {
        &self.state
    }

    /// Get gas used.
    pub fn gas_used(&self) -> u64 {
        self.gas_used
    }

    /// Get receipts.
    pub fn receipts(&self) -> &[Receipt] {
        &self.receipts
    }
}

// -----------------------------------------------------------------------------
// Single Transaction Application (Full Version)
// -----------------------------------------------------------------------------

/// Apply a single transaction — evolve the state under Ĥ_tx.
///
/// This is the core quantum evolution function. It returns the receipt and
/// the new state. It handles all sub-systems: KV, VM, Staking, etc.
pub fn apply_tx(
    state: &KvState,
    tx: &Tx,
    base_fee_per_gas: u64,
    proposer_addr: &str,
    econ_params: &EconomicsParams,
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

    // Now handle payload: KV, Staking, VM, EVM
    let mut after = working.clone();

    // Check if it's a staking transaction (prefixed with "staking:")
    if tx.payload.starts_with("staking:") {
        let staking_payload = tx.payload.strip_prefix("staking:").unwrap_or("");
        match try_apply_staking_tx(&mut after.kv, staking_payload, &from_addr) {
            Ok(()) => {
                receipt.success = true;
                after.apply_decoherence(0.002);
                // Update gas used (staking uses extra gas)
                let staking_gas = 1000; // approximate
                receipt.gas_used = receipt.gas_used.saturating_add(staking_gas);
                receipt.exec_gas_used = staking_gas;
                return (receipt, after);
            }
            Err(e) => {
                receipt.error = Some(format!("staking error: {e}"));
                return (receipt, after);
            }
        }
    }

    // VM/WebAssembly payload
    if tx.payload.trim_start().starts_with("vm ") {
        let vm_payload = tx.payload.trim_start().strip_prefix("vm ").unwrap_or("");
        match parse_vm_payload(vm_payload) {
            Ok(VmTxPayload::Deploy { code, params }) => {
                let (result, gas_used) = vm_deploy(&mut after.vm, &code, &params);
                receipt.vm_gas_used = gas_used;
                receipt.gas_used = receipt.gas_used.saturating_add(gas_used);
                match result {
                    Ok(addr) => {
                        receipt.success = true;
                        receipt.data = Some(hex::encode(addr));
                    }
                    Err(e) => {
                        receipt.error = Some(format!("vm deploy error: {e}"));
                    }
                }
                after.apply_decoherence(0.003);
                return (receipt, after);
            }
            Ok(VmTxPayload::Call { contract, method, args }) => {
                let (result, gas_used) = vm_call(&mut after.vm, &contract, &method, &args);
                receipt.vm_gas_used = gas_used;
                receipt.gas_used = receipt.gas_used.saturating_add(gas_used);
                match result {
                    Ok(data) => {
                        receipt.success = true;
                        receipt.data = Some(hex::encode(&data));
                    }
                    Err(e) => {
                        receipt.error = Some(format!("vm call error: {e}"));
                    }
                }
                after.apply_decoherence(0.003);
                return (receipt, after);
            }
            Err(e) => {
                receipt.error = Some(format!("vm payload parse error: {e}"));
                return (receipt, after);
            }
        }
    }

    // EVM payload (not yet implemented, placeholder)
    // For now, treat as regular KV if not matched above.
    // Apply payload gate
    match apply_payload_kv(&mut after.kv, &tx.payload) {
        Ok(()) => {
            receipt.success = true;
            after.apply_decoherence(0.001);
            (receipt, after)
        }
        Err(e) => {
            receipt.error = Some(e.to_string());
            (receipt, working) // revert to pre-payload state
        }
    }
}

// -----------------------------------------------------------------------------
// Block Execution
// -----------------------------------------------------------------------------

/// Execute a block using the TransactionExecutor for optimized execution.
pub fn execute_block(
    prev_state: &KvState,
    txs: &[Tx],
    base_fee_per_gas: u64,
    proposer_addr: &str,
    econ_params: &EconomicsParams,
    max_gas_per_block: u64,
) -> (KvState, u64, Vec<Receipt>) {
    let mut executor = TransactionExecutor::new(
        prev_state.clone(),
        proposer_addr,
        base_fee_per_gas,
        max_gas_per_block,
        econ_params.clone(),
    );

    // Use parallel execution if large batch.
    let result = if txs.len() > QUANTUM_PARALLEL_THRESHOLD {
        executor.execute_batch_parallel(txs)
    } else {
        executor.execute_batch(txs)
    };

    if let Err(e) = result {
        // Log error but continue with whatever was executed.
        error!("Block execution error: {}", e);
    }

    let (final_state, receipts, gas_used) = executor.finalize();
    (final_state, gas_used, receipts)
}

// -----------------------------------------------------------------------------
// EIP-1559 Base Fee — Harmonic Oscillator Model
// -----------------------------------------------------------------------------

/// Compute next base fee using quantum harmonic oscillator analogy.
pub fn next_base_fee(prev_base: u64, gas_used: u64, gas_target: u64) -> u64 {
    if gas_target == 0 {
        return prev_base.max(1);
    }

    let prev_base = prev_base.max(1);
    const ELASTICITY_DENOM: u64 = 4;

    if gas_used > gas_target {
        let excess = gas_used - gas_target;
        (prev_base + (prev_base * excess / gas_target / ELASTICITY_DENOM).max(1)).max(1)
    } else {
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
    econ_params: &EconomicsParams,
    txs: Vec<Tx>,
    max_gas_per_block: u64,
) -> (Block, KvState, Vec<Receipt>) {
    let (st, gas_used, receipts) = execute_block(
        prev_state,
        &txs,
        base_fee_per_gas,
        proposer_addr,
        econ_params,
        max_gas_per_block,
    );

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
    econ_params: &EconomicsParams,
    max_gas_per_block: u64,
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
        econ_params,
        max_gas_per_block,
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
    econ_params: &EconomicsParams,
    max_gas_per_block: u64,
) -> Option<(KvState, Vec<Receipt>)> {
    if block.header.proposer_pk != expected_pk.0 {
        return None;
    }
    verify_block(prev_state, block, proposer_addr, econ_params, max_gas_per_block)
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::ed25519::{Ed25519KeyPair, KeyPair};
    use crate::types::Tx;
    use tempfile::tempdir;

    fn create_test_tx(seed: u64, nonce: u64, payload: &str) -> Tx {
        let kp = Ed25519KeyPair::from_seed(seed.to_le_bytes());
        let pubkey = kp.public_key_bytes().0;
        let from = derive_address(&pubkey);
        let mut tx = Tx {
            from,
            pubkey,
            nonce,
            gas_limit: 100_000,
            max_fee_per_gas: 100,
            max_priority_fee_per_gas: 10,
            payload: payload.to_string(),
            signature: vec![0; 64],
        };
        let msg = tx_sign_bytes(&tx);
        let sig = kp.sign(&msg);
        tx.signature = sig.0;
        tx
    }

    fn create_test_state() -> KvState {
        let mut state = KvState::default();
        // Give some balance to test accounts.
        let kp = Ed25519KeyPair::from_seed(1u64.to_le_bytes());
        let addr = derive_address(&kp.public_key_bytes().0);
        state.balances.insert(addr, 1_000_000);
        state
    }

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

    #[test]
    fn test_apply_tx_kv_set() {
        let state = create_test_state();
        let tx = create_test_tx(1, 0, "set foo bar");
        let econ_params = EconomicsParams::default();
        let (receipt, new_state) = apply_tx(&state, &tx, 10, "proposer", &econ_params);
        assert!(receipt.success);
        assert_eq!(new_state.kv.get("foo"), Some(&"bar".to_string()));
    }

    #[test]
    fn test_apply_tx_kv_inc() {
        let mut state = create_test_state();
        state.kv.insert("counter".into(), "5".into());
        let tx = create_test_tx(1, 0, "inc counter");
        let econ_params = EconomicsParams::default();
        let (receipt, new_state) = apply_tx(&state, &tx, 10, "proposer", &econ_params);
        assert!(receipt.success);
        assert_eq!(new_state.kv.get("counter"), Some(&"6".to_string()));
    }

    #[test]
    fn test_executor_single() {
        let state = create_test_state();
        let mut executor = TransactionExecutor::new(
            state,
            "proposer",
            10,
            1_000_000,
            EconomicsParams::default(),
        );
        let tx = create_test_tx(1, 0, "set foo bar");
        let receipt = executor.execute_tx(&tx).unwrap();
        assert!(receipt.success);
        assert_eq!(executor.state().kv.get("foo"), Some(&"bar".to_string()));
    }

    #[test]
    fn test_executor_batch_parallel() {
        let state = create_test_state();
        let mut executor = TransactionExecutor::new(
            state,
            "proposer",
            10,
            1_000_000,
            EconomicsParams::default(),
        );
        let txs: Vec<Tx> = (0..20)
            .map(|i| create_test_tx(i as u64 + 1, 0, format!("set key{} value{}", i, i)))
            .collect();
        let receipts = executor.execute_batch_parallel(&txs).unwrap();
        assert_eq!(receipts.len(), 20);
        for i in 0..20 {
            let key = format!("key{}", i);
            assert_eq!(executor.state().kv.get(&key), Some(&format!("value{}", i)));
        }
    }

    #[test]
    fn test_executor_gas_limit() {
        let state = create_test_state();
        let mut executor = TransactionExecutor::new(
            state,
            "proposer",
            10,
            100, // very low gas limit
            EconomicsParams::default(),
        );
        let tx = create_test_tx(1, 0, "set foo bar");
        let result = executor.execute_tx(&tx);
        assert!(result.is_err());
        if let Err(ExecutionError::GasOverflow { limit }) = result {
            assert_eq!(limit, 100);
        } else {
            panic!("Expected GasOverflow");
        }
    }
}
