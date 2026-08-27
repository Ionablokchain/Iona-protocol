//! Quantum state transition and transaction execution.
//!
//! # Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────────────────┐
//! │                        Execution Module                                │
//! ├─────────────┬──────────────┬───────────────┬──────────────────────────┤
//! │   Config    │    Error     │    Metrics    │         State            │
//! │ (ExeCfg)    │ (ExeError)   │ (ExeMetrics)  │ (KvState, QuantumState)  │
//! ├─────────────┼──────────────┼───────────────┼──────────────────────────┤
//! │  Executor   │  Apply       │  Block        │        Manager           │
//! │ (TxExecutor)│ (apply_tx)   │ (build/verify)│ (ExeManager)             │
//! ├─────────────┼──────────────┼───────────────┼──────────────────────────┤
//! │   Parallel  │  Fee         │               │                          │
//! │ (parallel)  │ (next_base)  │               │                          │
//! └─────────────────────────────────────────────────────────────────────────┘
//! ```
//!
//! # Example
//!
//! ```rust,ignore
//! use iona::execution::{ExecutionManager, ExecutionConfig};
//!
//! let config = ExecutionConfig::default();
//! let mut manager = ExecutionManager::new(config);
//! let (new_state, gas_used, receipts) = manager.execute_block(prev_state, &txs, base_fee, proposer)?;
//! ```

#![allow(dead_code)]

// -----------------------------------------------------------------------------
// Submodules (embedded)
// -----------------------------------------------------------------------------

pub mod parallel;
pub mod sandbox;
pub mod vm_executor;

// -----------------------------------------------------------------------------
// Inline submodules for the manager
// -----------------------------------------------------------------------------

mod config {
    //! Configuration for the execution subsystem.
    use serde::{Deserialize, Serialize};
    use crate::economics::params::EconomicsParams;

    /// Configuration for execution.
    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct ExecutionConfig {
        pub default_max_gas_per_block: u64,
        pub quantum_parallel_threshold: usize,
        pub entanglement_threshold: f64,
        pub tx_coherence_time: u64,
        pub verify_signatures: bool,
        pub collect_metrics: bool,
        pub log_operations: bool,
        pub economics_params: EconomicsParams,
    }

    impl Default for ExecutionConfig {
        fn default() -> Self {
            Self {
                default_max_gas_per_block: super::constants::DEFAULT_MAX_GAS_PER_BLOCK,
                quantum_parallel_threshold: super::constants::QUANTUM_PARALLEL_THRESHOLD,
                entanglement_threshold: super::constants::ENTANGLEMENT_THRESHOLD,
                tx_coherence_time: super::constants::TX_COHERENCE_TIME,
                verify_signatures: true,
                collect_metrics: true,
                log_operations: false,
                economics_params: EconomicsParams::default(),
            }
        }
    }

    impl ExecutionConfig {
        pub fn validate(&self) -> Result<(), &'static str> {
            if self.default_max_gas_per_block == 0 {
                return Err("default_max_gas_per_block must be > 0");
            }
            if self.quantum_parallel_threshold == 0 {
                return Err("quantum_parallel_threshold must be > 0");
            }
            if self.entanglement_threshold < 0.0 || self.entanglement_threshold > 1.0 {
                return Err("entanglement_threshold must be between 0 and 1");
            }
            if self.tx_coherence_time == 0 {
                return Err("tx_coherence_time must be > 0");
            }
            Ok(())
        }

        pub fn with_metrics(mut self) -> Self {
            self.collect_metrics = true;
            self
        }
    }
}

mod error {
    //! Errors for quantum state transitions.
    use crate::types::Hash32;
    use thiserror::Error;

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
}

mod constants {
    //! Constants for the execution subsystem.

    /// Reduced Planck constant (natural units).
    pub const HBAR: f64 = 1.0;

    /// Entanglement threshold for parallel execution.
    pub const ENTANGLEMENT_THRESHOLD: f64 = 0.5;

    /// Coherence time for transaction execution (steps).
    pub const TX_COHERENCE_TIME: u64 = 1000;

    /// Minimum transactions for quantum parallelism.
    pub const QUANTUM_PARALLEL_THRESHOLD: usize = 16;

    /// Default max gas per block.
    pub const DEFAULT_MAX_GAS_PER_BLOCK: u64 = 30_000_000;

    /// Intrinsic gas base.
    pub const INTRINSIC_GAS_BASE: u64 = 21_000;

    /// Gas per byte.
    pub const GAS_PER_BYTE: u64 = 10;

    /// EIP-1559 elasticity denominator.
    pub const ELASTICITY_DENOM: u64 = 4;

    /// Default chain ID.
    pub const DEFAULT_CHAIN_ID: u64 = 6126151;
}

mod metrics {
    //! Metrics for execution operations.
    use core::sync::atomic::{AtomicU64, Ordering};
    use serde::{Deserialize, Serialize};

    #[derive(Debug, Default)]
    pub struct ExecutionMetrics {
        pub txs_executed: AtomicU64,
        pub txs_failed: AtomicU64,
        pub blocks_executed: AtomicU64,
        pub blocks_verified: AtomicU64,
        pub gas_used_total: AtomicU64,
        pub gas_refunded_total: AtomicU64,
        pub parallel_executions: AtomicU64,
        pub sequential_executions: AtomicU64,
        pub state_merges: AtomicU64,
        pub decoherence_applied: AtomicU64,
        pub signature_verifications: AtomicU64,
        pub signature_failures: AtomicU64,
    }

    impl ExecutionMetrics {
        pub fn inc_tx_executed(&self, success: bool) {
            self.txs_executed.fetch_add(1, Ordering::Relaxed);
            if !success {
                self.txs_failed.fetch_add(1, Ordering::Relaxed);
            }
        }

        pub fn inc_block_executed(&self) {
            self.blocks_executed.fetch_add(1, Ordering::Relaxed);
        }

        pub fn inc_block_verified(&self) {
            self.blocks_verified.fetch_add(1, Ordering::Relaxed);
        }

        pub fn add_gas_used(&self, gas: u64) {
            self.gas_used_total.fetch_add(gas, Ordering::Relaxed);
        }

        pub fn add_gas_refunded(&self, gas: u64) {
            self.gas_refunded_total.fetch_add(gas, Ordering::Relaxed);
        }

        pub fn inc_parallel(&self) {
            self.parallel_executions.fetch_add(1, Ordering::Relaxed);
        }

        pub fn inc_sequential(&self) {
            self.sequential_executions.fetch_add(1, Ordering::Relaxed);
        }

        pub fn inc_merge(&self) {
            self.state_merges.fetch_add(1, Ordering::Relaxed);
        }

        pub fn inc_decoherence(&self) {
            self.decoherence_applied.fetch_add(1, Ordering::Relaxed);
        }

        pub fn inc_signature_verification(&self, success: bool) {
            self.signature_verifications.fetch_add(1, Ordering::Relaxed);
            if !success {
                self.signature_failures.fetch_add(1, Ordering::Relaxed);
            }
        }

        pub fn snapshot(&self) -> ExecutionMetricsSnapshot {
            ExecutionMetricsSnapshot {
                txs_executed: self.txs_executed.load(Ordering::Relaxed),
                txs_failed: self.txs_failed.load(Ordering::Relaxed),
                blocks_executed: self.blocks_executed.load(Ordering::Relaxed),
                blocks_verified: self.blocks_verified.load(Ordering::Relaxed),
                gas_used_total: self.gas_used_total.load(Ordering::Relaxed),
                gas_refunded_total: self.gas_refunded_total.load(Ordering::Relaxed),
                parallel_executions: self.parallel_executions.load(Ordering::Relaxed),
                sequential_executions: self.sequential_executions.load(Ordering::Relaxed),
                state_merges: self.state_merges.load(Ordering::Relaxed),
                decoherence_applied: self.decoherence_applied.load(Ordering::Relaxed),
                signature_verifications: self.signature_verifications.load(Ordering::Relaxed),
                signature_failures: self.signature_failures.load(Ordering::Relaxed),
            }
        }
    }

    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct ExecutionMetricsSnapshot {
        pub txs_executed: u64,
        pub txs_failed: u64,
        pub blocks_executed: u64,
        pub blocks_verified: u64,
        pub gas_used_total: u64,
        pub gas_refunded_total: u64,
        pub parallel_executions: u64,
        pub sequential_executions: u64,
        pub state_merges: u64,
        pub decoherence_applied: u64,
        pub signature_verifications: u64,
        pub signature_failures: u64,
    }

    /// Global metrics instance.
    pub(crate) static GLOBAL_METRICS: spin::Once<ExecutionMetrics> = spin::Once::new();

    pub fn global_metrics() -> &'static ExecutionMetrics {
        GLOBAL_METRICS.get_or_init(ExecutionMetrics::default)
    }
}

mod state {
    //! Quantum state definition and operations.
    use super::{
        config::ExecutionConfig,
        error::ExecutionResult,
        constants::TX_COHERENCE_TIME,
        metrics::global_metrics,
    };
    use crate::merkle::state_merkle_root;
    use crate::types::Hash32;
    use crate::vm::state::VmStorage;
    use serde::{Deserialize, Serialize};
    use std::collections::BTreeMap;
    use std::fmt;

    /// The complete quantum state of the blockchain.
    #[derive(Clone, Debug, Default, Serialize, Deserialize)]
    pub struct KvState {
        pub kv: BTreeMap<String, String>,
        pub balances: BTreeMap<String, u64>,
        pub nonces: BTreeMap<String, u64>,
        pub burned: u64,
        pub vm: VmStorage,
        #[serde(default = "default_coherence")]
        pub coherence: f64,
        #[serde(default)]
        pub entanglement_entropy: f64,
    }

    fn default_coherence() -> f64 {
        1.0
    }

    impl KvState {
        /// Compute the deterministic Merkle state root.
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

            for ((contract, slot), value) in &self.vm.storage {
                let key = format!(
                    "vm_storage:{}:{}",
                    hex::encode(contract),
                    hex::encode(slot)
                );
                combined.insert(key, hex::encode(value));
            }

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
            global_metrics().inc_decoherence();
        }

        /// Create a deep clone for parallel execution isolation.
        pub fn fork(&self) -> Self {
            self.clone()
        }

        /// Merge another state into this one.
        pub fn merge(&mut self, other: &Self) -> ExecutionResult<()> {
            // Check for conflicts (overlapping keys, balances, nonces, etc.)
            for (k, v) in &other.kv {
                if let Some(existing) = self.kv.get(k) {
                    if existing != v {
                        return Err(super::error::ExecutionError::EntanglementBroken);
                    }
                }
            }
            for (addr, bal) in &other.balances {
                if let Some(existing) = self.balances.get(addr) {
                    if existing != bal {
                        return Err(super::error::ExecutionError::EntanglementBroken);
                    }
                }
            }
            for (addr, nonce) in &other.nonces {
                if let Some(existing) = self.nonces.get(addr) {
                    if existing != nonce {
                        return Err(super::error::ExecutionError::EntanglementBroken);
                    }
                }
            }
            for (key, val) in &other.vm.storage {
                if let Some(existing) = self.vm.storage.get(key) {
                    if existing != val {
                        return Err(super::error::ExecutionError::EntanglementBroken);
                    }
                }
            }
            for (contract, code) in &other.vm.code {
                if let Some(existing) = self.vm.code.get(contract) {
                    if existing != code {
                        return Err(super::error::ExecutionError::EntanglementBroken);
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
            global_metrics().inc_merge();
            Ok(())
        }
    }
}

mod fee {
    //! Fee calculation (EIP-1559).
    use super::constants::ELASTICITY_DENOM;

    /// Compute next base fee using quantum harmonic oscillator analogy.
    pub fn next_base_fee(prev_base: u64, gas_used: u64, gas_target: u64) -> u64 {
        if gas_target == 0 {
            return prev_base.max(1);
        }
        let prev_base = prev_base.max(1);
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

    /// Compute intrinsic gas.
    pub fn intrinsic_gas(payload: &str) -> u64 {
        super::constants::INTRINSIC_GAS_BASE + (payload.len() as u64).saturating_mul(super::constants::GAS_PER_BYTE)
    }
}

mod verify {
    //! Signature verification.
    use super::{
        error::{ExecutionError, ExecutionResult},
        metrics::global_metrics,
    };
    use crate::crypto::ed25519::Ed25519Verifier;
    use crate::crypto::tx::{derive_address, tx_sign_bytes};
    use crate::crypto::{PublicKeyBytes, SignatureBytes, Verifier};
    use crate::types::Tx;

    /// Verify transaction signature.
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

        let result = Ed25519Verifier::verify(&pk, &msg, &sig);
        global_metrics().inc_signature_verification(result.is_ok());
        result.map_err(|_| ExecutionError::InvalidSignature)?;
        Ok(addr)
    }
}

mod kv {
    //! KV payload application.
    use super::error::{ExecutionError, ExecutionResult};
    use std::collections::BTreeMap;

    /// Apply a KV payload.
    pub fn apply_kv_payload(kv: &mut BTreeMap<String, String>, payload: &str) -> ExecutionResult<()> {
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
}

mod apply {
    //! Single transaction application.
    use super::{
        config::ExecutionConfig,
        error::{ExecutionError, ExecutionResult},
        state::KvState,
        metrics::global_metrics,
        fee::intrinsic_gas,
        verify::verify_tx_signature,
        kv::apply_kv_payload,
        vm_executor::{parse_vm_payload, vm_call, vm_deploy, VmTxPayload},
    };
    use crate::economics::params::EconomicsParams;
    use crate::economics::staking_tx::try_apply_staking_tx;
    use crate::types::{Receipt, Tx};
    use tracing::{debug, trace};

    /// Apply a single transaction — evolve the state under Ĥ_tx.
    pub fn apply_tx(
        state: &KvState,
        tx: &Tx,
        base_fee_per_gas: u64,
        proposer_addr: &str,
        econ_params: &EconomicsParams,
        config: &ExecutionConfig,
    ) -> (Receipt, KvState) {
        let txh = crate::types::tx_hash(tx);

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
            Err(e) => {
                receipt.error = Some(e.to_string());
                global_metrics().inc_tx_executed(false);
                return (receipt, state.clone());
            }
        };

        let mut working = state.clone();
        working.apply_decoherence(0.001);

        let expected = *working.nonces.get(&from_addr).unwrap_or(&0);
        if tx.nonce != expected {
            receipt.error = Some(format!("bad nonce: expected {}, got {}", expected, tx.nonce));
            global_metrics().inc_tx_executed(false);
            return (receipt, state.clone());
        }

        let intrinsic = intrinsic_gas(&tx.payload);
        receipt.intrinsic_gas_used = intrinsic;
        receipt.gas_used = intrinsic;

        if tx.gas_limit < intrinsic {
            receipt.error = Some(format!("gas limit {} < intrinsic {}", tx.gas_limit, intrinsic));
            global_metrics().inc_tx_executed(false);
            return (receipt, state.clone());
        }

        if tx.max_fee_per_gas < base_fee_per_gas {
            receipt.error = Some(format!("max fee {} < base fee {}", tx.max_fee_per_gas, base_fee_per_gas));
            global_metrics().inc_tx_executed(false);
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
            receipt.error = Some(format!("insufficient balance: need {}, have {}", total, bal));
            global_metrics().inc_tx_executed(false);
            return (receipt, state.clone());
        }

        // Charge fee + increment nonce
        working.balances.insert(from_addr.clone(), bal - total);
        working.burned = working.burned.saturating_add(burned);
        let pb = *working.balances.get(proposer_addr).unwrap_or(&0);
        working.balances.insert(proposer_addr.to_string(), pb.saturating_add(tip));
        working.nonces.insert(from_addr.clone(), expected + 1);

        let mut after = working.clone();

        // Payload handling
        if tx.payload.starts_with("staking:") {
            let staking_payload = tx.payload.strip_prefix("staking:").unwrap_or("");
            match try_apply_staking_tx(&mut after.kv, staking_payload, &from_addr) {
                Ok(()) => {
                    receipt.success = true;
                    after.apply_decoherence(0.002);
                    let staking_gas = 1000;
                    receipt.gas_used = receipt.gas_used.saturating_add(staking_gas);
                    receipt.exec_gas_used = staking_gas;
                    global_metrics().inc_tx_executed(true);
                    return (receipt, after);
                }
                Err(e) => {
                    receipt.error = Some(format!("staking error: {e}"));
                    global_metrics().inc_tx_executed(false);
                    return (receipt, after);
                }
            }
        }

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
                    global_metrics().inc_tx_executed(receipt.success);
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
                    global_metrics().inc_tx_executed(receipt.success);
                    return (receipt, after);
                }
                Err(e) => {
                    receipt.error = Some(format!("vm payload parse error: {e}"));
                    global_metrics().inc_tx_executed(false);
                    return (receipt, after);
                }
            }
        }

        // KV payload
        match apply_kv_payload(&mut after.kv, &tx.payload) {
            Ok(()) => {
                receipt.success = true;
                after.apply_decoherence(0.001);
                global_metrics().inc_tx_executed(true);
                (receipt, after)
            }
            Err(e) => {
                receipt.error = Some(e.to_string());
                global_metrics().inc_tx_executed(false);
                (receipt, working) // revert
            }
        }
    }
}

mod executor {
    //! Transaction executor with state management and atomicity.
    use super::{
        config::ExecutionConfig,
        error::{ExecutionError, ExecutionResult},
        state::KvState,
        metrics::global_metrics,
        apply::apply_tx,
        constants::QUANTUM_PARALLEL_THRESHOLD,
    };
    use crate::economics::params::EconomicsParams;
    use crate::types::{Hash32, Receipt, Tx};
    use rayon::prelude::*;
    use std::collections::HashSet;
    use tracing::{debug, trace, warn};

    /// Main transaction executor.
    pub struct TransactionExecutor {
        state: KvState,
        econ_params: EconomicsParams,
        proposer: String,
        max_gas_per_block: u64,
        base_fee: u64,
        executed_hashes: HashSet<Hash32>,
        gas_used: u64,
        receipts: Vec<Receipt>,
        config: ExecutionConfig,
    }

    impl TransactionExecutor {
        pub fn new(
            state: KvState,
            proposer: impl Into<String>,
            base_fee_per_gas: u64,
            max_gas: u64,
            econ_params: EconomicsParams,
            config: ExecutionConfig,
        ) -> Self {
            Self {
                state,
                econ_params,
                proposer: proposer.into(),
                max_gas_per_block: if max_gas == 0 { config.default_max_gas_per_block } else { max_gas },
                base_fee: base_fee_per_gas,
                executed_hashes: HashSet::new(),
                gas_used: 0,
                receipts: Vec::new(),
                config,
            }
        }

        pub fn execute_tx(&mut self, tx: &Tx) -> ExecutionResult<&Receipt> {
            let txh = crate::types::tx_hash(tx);
            if !self.executed_hashes.insert(txh) {
                return Err(ExecutionError::DuplicateTx {
                    hash: hex::encode(txh.as_bytes()),
                });
            }

            let (receipt, new_state) = apply_tx(
                &self.state,
                tx,
                self.base_fee,
                &self.proposer,
                &self.econ_params,
                &self.config,
            );

            self.gas_used = self.gas_used.saturating_add(receipt.gas_used);
            if self.gas_used > self.max_gas_per_block {
                return Err(ExecutionError::GasOverflow {
                    limit: self.max_gas_per_block,
                });
            }

            self.state = new_state;
            self.receipts.push(receipt);
            global_metrics().add_gas_used(receipt.gas_used);
            Ok(self.receipts.last().unwrap())
        }

        pub fn execute_batch(&mut self, txs: &[Tx]) -> ExecutionResult<Vec<&Receipt>> {
            let mut results = Vec::with_capacity(txs.len());
            for tx in txs {
                let receipt = self.execute_tx(tx)?;
                results.push(receipt);
            }
            Ok(results)
        }

        pub fn execute_batch_parallel(&mut self, txs: &[Tx]) -> ExecutionResult<Vec<&Receipt>> {
            if txs.len() <= QUANTUM_PARALLEL_THRESHOLD || !self.config.verify_signatures {
                return self.execute_batch(txs);
            }

            // Parallel signature verification.
            use super::verify::verify_tx_signature;
            let sig_results: Vec<Result<String, ExecutionError>> = txs
                .par_iter()
                .map(|tx| verify_tx_signature(tx))
                .collect();

            let mut failed = Vec::new();
            for (i, result) in sig_results.iter().enumerate() {
                if result.is_err() {
                    failed.push(i);
                }
            }
            if !failed.is_empty() {
                return Err(ExecutionError::InvalidTx(format!(
                    "{} transactions have invalid signatures",
                    failed.len()
                )));
            }

            let base_state = &self.state;
            let base_fee = self.base_fee;
            let proposer = self.proposer.clone();
            let econ_params = self.econ_params.clone();
            let config = self.config.clone();

            let results: Vec<Result<(Receipt, KvState), ExecutionError>> = txs
                .par_iter()
                .enumerate()
                .map(|(i, tx)| {
                    if sig_results[i].is_err() {
                        return Err(ExecutionError::InvalidSignature);
                    }
                    let (receipt, partial_state) = apply_tx(
                        base_state,
                        tx,
                        base_fee,
                        &proposer,
                        &econ_params,
                        &config,
                    );
                    if receipt.success {
                        Ok((receipt, partial_state))
                    } else {
                        Err(ExecutionError::InvalidTx(receipt.error.clone().unwrap_or_else(|| "unknown".into())))
                    }
                })
                .collect();

            let mut final_state = self.state.clone();
            let mut all_receipts = Vec::with_capacity(txs.len());
            let mut total_gas = 0u64;
            let mut all_success = true;

            for result in results {
                match result {
                    Ok((receipt, partial_state)) => {
                        final_state.merge(&partial_state)?;
                        all_receipts.push(receipt.clone());
                        total_gas = total_gas.saturating_add(receipt.gas_used);
                        if !receipt.success {
                            all_success = false;
                        }
                    }
                    Err(e) => {
                        return Err(e);
                    }
                }
            }

            if total_gas > self.max_gas_per_block {
                return Err(ExecutionError::GasOverflow {
                    limit: self.max_gas_per_block,
                });
            }

            self.state = final_state;
            self.gas_used = total_gas;
            self.receipts.extend(all_receipts);
            global_metrics().add_gas_used(total_gas);
            global_metrics().inc_parallel();

            Ok(self.receipts.iter().collect())
        }

        pub fn finalize(self) -> (KvState, Vec<Receipt>, u64) {
            (self.state, self.receipts, self.gas_used)
        }

        pub fn state(&self) -> &KvState {
            &self.state
        }

        pub fn gas_used(&self) -> u64 {
            self.gas_used
        }

        pub fn receipts(&self) -> &[Receipt] {
            &self.receipts
        }
    }
}

mod block {
    //! Block building and verification.
    use super::{
        config::ExecutionConfig,
        error::ExecutionResult,
        state::KvState,
        executor::TransactionExecutor,
        metrics::global_metrics,
        fee::next_base_fee,
        constants::DEFAULT_CHAIN_ID,
    };
    use crate::economics::params::EconomicsParams;
    use crate::types::{Block, BlockHeader, Hash32, Height, Receipt, Round, Tx, tx_root, receipts_root};
    use std::time::{SystemTime, UNIX_EPOCH};
    use tracing::{debug, info, trace};

    /// Build a new block.
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
        config: &ExecutionConfig,
    ) -> (Block, KvState, Vec<Receipt>) {
        let mut executor = TransactionExecutor::new(
            prev_state.clone(),
            proposer_addr,
            base_fee_per_gas,
            max_gas_per_block,
            econ_params.clone(),
            config.clone(),
        );

        let result = if txs.len() > config.quantum_parallel_threshold {
            executor.execute_batch_parallel(&txs)
        } else {
            executor.execute_batch(&txs)
        };

        if let Err(e) = result {
            // Log error but continue with whatever was executed.
            tracing::error!("Block execution error: {}", e);
        }

        let (st, receipts, gas_used) = executor.finalize();

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
            chain_id: DEFAULT_CHAIN_ID,
            timestamp: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0),
            protocol_version: crate::protocol::version::CURRENT_PROTOCOL_VERSION,
        };

        global_metrics().inc_block_executed();
        debug!(height, round, txs = txs.len(), gas_used, "block built");
        (Block { header, txs }, st, receipts)
    }

    /// Verify a block.
    pub fn verify_block(
        prev_state: &KvState,
        block: &Block,
        proposer_addr: &str,
        econ_params: &EconomicsParams,
        max_gas_per_block: u64,
        config: &ExecutionConfig,
    ) -> Option<(KvState, Vec<Receipt>)> {
        if block.header.proposer_pk.len() != 32 {
            return None;
        }

        if tx_root(&block.txs) != block.header.tx_root {
            return None;
        }

        let mut executor = TransactionExecutor::new(
            prev_state.clone(),
            proposer_addr,
            block.header.base_fee_per_gas,
            max_gas_per_block,
            econ_params.clone(),
            config.clone(),
        );

        let result = if block.txs.len() > config.quantum_parallel_threshold {
            executor.execute_batch_parallel(&block.txs)
        } else {
            executor.execute_batch(&block.txs)
        };

        if let Err(e) = result {
            tracing::warn!("Block verification execution failed: {}", e);
            return None;
        }

        let (st, receipts, gas_used) = executor.finalize();

        if gas_used != block.header.gas_used {
            return None;
        }

        if receipts_root(&receipts) != block.header.receipts_root {
            return None;
        }

        if st.root() != block.header.state_root {
            return None;
        }

        global_metrics().inc_block_verified();
        debug!(height = block.header.height, txs = block.txs.len(), gas_used, "block verified");
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
        config: &ExecutionConfig,
    ) -> Option<(KvState, Vec<Receipt>)> {
        if block.header.proposer_pk != expected_pk.0 {
            return None;
        }
        verify_block(prev_state, block, proposer_addr, econ_params, max_gas_per_block, config)
    }
}

mod manager {
    //! Centralised manager for execution.
    use super::{
        config::ExecutionConfig,
        error::{ExecutionError, ExecutionResult},
        metrics::{ExecutionMetrics, global_metrics},
        state::KvState,
        block::{build_block, verify_block, verify_block_with_vset},
        executor::TransactionExecutor,
        fee::next_base_fee,
    };
    use crate::economics::params::EconomicsParams;
    use crate::types::{Block, Hash32, Height, Receipt, Round, Tx};
    use core::sync::atomic::Ordering;
    use tracing::{debug, info};

    /// Manager for execution operations.
    pub struct ExecutionManager {
        config: ExecutionConfig,
        initialised: bool,
    }

    impl ExecutionManager {
        pub fn new(config: ExecutionConfig) -> Self {
            config.validate().expect("invalid ExecutionConfig");
            Self {
                config,
                initialised: false,
            }
        }

        pub fn default() -> Self {
            Self::new(ExecutionConfig::default())
        }

        pub fn config(&self) -> &ExecutionConfig {
            &self.config
        }

        pub fn init(&mut self) {
            self.initialised = true;
            info!("execution manager initialised");
        }

        pub fn is_initialised(&self) -> bool {
            self.initialised
        }

        /// Execute a single transaction.
        pub fn apply_tx(
            &self,
            state: &KvState,
            tx: &Tx,
            base_fee_per_gas: u64,
            proposer_addr: &str,
            econ_params: &EconomicsParams,
        ) -> (Receipt, KvState) {
            super::apply::apply_tx(state, tx, base_fee_per_gas, proposer_addr, econ_params, &self.config)
        }

        /// Execute a block.
        pub fn execute_block(
            &self,
            prev_state: &KvState,
            txs: &[Tx],
            base_fee_per_gas: u64,
            proposer_addr: &str,
            econ_params: &EconomicsParams,
            max_gas_per_block: u64,
        ) -> ExecutionResult<(KvState, u64, Vec<Receipt>)> {
            let mut executor = TransactionExecutor::new(
                prev_state.clone(),
                proposer_addr,
                base_fee_per_gas,
                max_gas_per_block,
                econ_params.clone(),
                self.config.clone(),
            );

            let result = if txs.len() > self.config.quantum_parallel_threshold {
                executor.execute_batch_parallel(txs)
            } else {
                executor.execute_batch(txs)
            };

            if let Err(e) = result {
                // Log error but continue with whatever was executed.
                tracing::error!("Block execution error: {}", e);
                // Return whatever was executed.
            }

            let (final_state, receipts, gas_used) = executor.finalize();
            Ok((final_state, gas_used, receipts))
        }

        /// Build a new block.
        pub fn build_block(
            &self,
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
            block::build_block(
                height, round, prev, proposer_pk, proposer_addr,
                prev_state, base_fee_per_gas, econ_params,
                txs, max_gas_per_block, &self.config,
            )
        }

        /// Verify a block.
        pub fn verify_block(
            &self,
            prev_state: &KvState,
            block: &Block,
            proposer_addr: &str,
            econ_params: &EconomicsParams,
            max_gas_per_block: u64,
        ) -> Option<(KvState, Vec<Receipt>)> {
            block::verify_block(
                prev_state, block, proposer_addr,
                econ_params, max_gas_per_block, &self.config,
            )
        }

        /// Verify a block with expected proposer public key.
        pub fn verify_block_with_vset(
            &self,
            prev_state: &KvState,
            block: &Block,
            proposer_addr: &str,
            expected_pk: &crate::crypto::PublicKeyBytes,
            econ_params: &EconomicsParams,
            max_gas_per_block: u64,
        ) -> Option<(KvState, Vec<Receipt>)> {
            block::verify_block_with_vset(
                prev_state, block, proposer_addr, expected_pk,
                econ_params, max_gas_per_block, &self.config,
            )
        }

        /// Compute next base fee.
        pub fn next_base_fee(&self, prev_base: u64, gas_used: u64, gas_target: u64) -> u64 {
            next_base_fee(prev_base, gas_used, gas_target)
        }

        /// Get metrics snapshot.
        pub fn metrics_snapshot(&self) -> super::metrics::ExecutionMetricsSnapshot {
            global_metrics().snapshot()
        }

        /// Reset metrics.
        pub fn reset_metrics(&self) {
            // Global metrics cannot be easily reset; we'll warn.
            tracing::warn!("resetting execution metrics not supported in this version");
        }
    }
}

// -----------------------------------------------------------------------------
// Public exports
// -----------------------------------------------------------------------------

pub use config::ExecutionConfig;
pub use error::{ExecutionError, ExecutionResult};
pub use state::KvState;
pub use metrics::{ExecutionMetrics, ExecutionMetricsSnapshot};
pub use manager::ExecutionManager;
pub use executor::TransactionExecutor;
pub use apply::apply_tx;
pub use block::{build_block, verify_block, verify_block_with_vset};
pub use fee::next_base_fee;
pub use verify::verify_tx_signature;
pub use kv::apply_kv_payload;
pub use super::parallel;
pub use super::sandbox;
pub use super::vm_executor;

// Re-export constants for backward compatibility.
pub use constants::*;

// -----------------------------------------------------------------------------
// Legacy global functions (backward compatibility)
// -----------------------------------------------------------------------------

use spin::Once;

static GLOBAL_MANAGER: Once<ExecutionManager> = Once::new();

fn global_manager() -> &'static ExecutionManager {
    GLOBAL_MANAGER.get_or_init(|| {
        let mut mgr = ExecutionManager::new(ExecutionConfig::default());
        mgr.init();
        mgr
    })
}

/// Apply a transaction (legacy).
pub fn apply_tx_legacy(
    state: &KvState,
    tx: &Tx,
    base_fee_per_gas: u64,
    proposer_addr: &str,
    econ_params: &EconomicsParams,
) -> (Receipt, KvState) {
    global_manager().apply_tx(state, tx, base_fee_per_gas, proposer_addr, econ_params)
}

/// Execute a block (legacy).
pub fn execute_block_legacy(
    prev_state: &KvState,
    txs: &[Tx],
    base_fee_per_gas: u64,
    proposer_addr: &str,
    econ_params: &EconomicsParams,
    max_gas_per_block: u64,
) -> (KvState, u64, Vec<Receipt>) {
    let result = global_manager().execute_block(
        prev_state, txs, base_fee_per_gas, proposer_addr, econ_params, max_gas_per_block,
    );
    match result {
        Ok((state, gas, receipts)) => (state, gas, receipts),
        Err(e) => {
            tracing::error!("Block execution failed: {}", e);
            (prev_state.clone(), 0, Vec::new())
        }
    }
}

/// Build a block (legacy).
pub fn build_block_legacy(
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
    global_manager().build_block(
        height, round, prev, proposer_pk, proposer_addr,
        prev_state, base_fee_per_gas, econ_params,
        txs, max_gas_per_block,
    )
}

/// Verify a block (legacy).
pub fn verify_block_legacy(
    prev_state: &KvState,
    block: &Block,
    proposer_addr: &str,
    econ_params: &EconomicsParams,
    max_gas_per_block: u64,
) -> Option<(KvState, Vec<Receipt>)> {
    global_manager().verify_block(prev_state, block, proposer_addr, econ_params, max_gas_per_block)
}

/// Next base fee (legacy).
pub fn next_base_fee_legacy(prev_base: u64, gas_used: u64, gas_target: u64) -> u64 {
    next_base_fee(prev_base, gas_used, gas_target)
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::ed25519::{Ed25519KeyPair, KeyPair};
    use crate::crypto::tx::derive_address;
    use crate::types::Tx;

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
        let msg = crate::crypto::tx::tx_sign_bytes(&tx);
        let sig = kp.sign(&msg);
        tx.signature = sig.0;
        tx
    }

    fn create_test_state() -> KvState {
        let mut state = KvState::default();
        let kp = Ed25519KeyPair::from_seed(1u64.to_le_bytes());
        let addr = derive_address(&kp.public_key_bytes().0);
        state.balances.insert(addr, 1_000_000);
        state
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
    fn test_apply_tx_kv_set() {
        let state = create_test_state();
        let tx = create_test_tx(1, 0, "set foo bar");
        let econ_params = EconomicsParams::default();
        let config = ExecutionConfig::default();
        let (receipt, new_state) = apply_tx(&state, &tx, 10, "proposer", &econ_params, &config);
        assert!(receipt.success);
        assert_eq!(new_state.kv.get("foo"), Some(&"bar".to_string()));
    }

    #[test]
    fn test_apply_tx_kv_inc() {
        let mut state = create_test_state();
        state.kv.insert("counter".into(), "5".into());
        let tx = create_test_tx(1, 0, "inc counter");
        let econ_params = EconomicsParams::default();
        let config = ExecutionConfig::default();
        let (receipt, new_state) = apply_tx(&state, &tx, 10, "proposer", &econ_params, &config);
        assert!(receipt.success);
        assert_eq!(new_state.kv.get("counter"), Some(&"6".to_string()));
    }

    #[test]
    fn test_executor_single() {
        let state = create_test_state();
        let config = ExecutionConfig::default();
        let mut executor = TransactionExecutor::new(
            state,
            "proposer",
            10,
            1_000_000,
            EconomicsParams::default(),
            config,
        );
        let tx = create_test_tx(1, 0, "set foo bar");
        let receipt = executor.execute_tx(&tx).unwrap();
        assert!(receipt.success);
        assert_eq!(executor.state().kv.get("foo"), Some(&"bar".to_string()));
    }

    #[test]
    fn test_executor_gas_limit() {
        let state = create_test_state();
        let config = ExecutionConfig::default();
        let mut executor = TransactionExecutor::new(
            state,
            "proposer",
            10,
            100, // very low
            EconomicsParams::default(),
            config,
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

    #[test]
    fn test_manager_apply_tx() {
        let mgr = ExecutionManager::default();
        let state = create_test_state();
        let tx = create_test_tx(1, 0, "set foo bar");
        let econ_params = EconomicsParams::default();
        let (receipt, new_state) = mgr.apply_tx(&state, &tx, 10, "proposer", &econ_params);
        assert!(receipt.success);
        assert_eq!(new_state.kv.get("foo"), Some(&"bar".to_string()));
    }
}
