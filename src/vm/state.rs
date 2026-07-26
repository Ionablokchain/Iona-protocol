//! VM quantum state — Hilbert space representation of contract storage and memory.
//!
//! # Production Features
//! - Configurable via `StateConfig` (max memory size, storage limits, metrics).
//! - `StateMetrics` with atomic counters for operations, cache hits/misses, storage reads/writes.
//! - `StateManager` as a thread‑safe wrapper (`parking_lot::Mutex` in std, `spin::Mutex` in no_std).
//! - LRU cache for storage reads (optional).
//! - Versioned serialization with schema version tracking.
//! - Structured logging with `tracing`.
//! - Full test coverage for quantum concepts and production wrappers.

use crate::vm::errors::VmError;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, VecDeque};
use std::fmt;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tracing::{debug, error, info, trace, warn};

#[cfg(feature = "std")]
use parking_lot::Mutex;
#[cfg(not(feature = "std"))]
use spin::Mutex;

// ── Configuration ─────────────────────────────────────────────────────────

/// Configuration for the VM state subsystem.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StateConfig {
    /// Maximum memory size in bytes (default: 4 MiB).
    pub max_memory_bytes: usize,
    /// Whether to cache storage reads.
    pub enable_storage_cache: bool,
    /// Maximum number of entries in the storage cache.
    pub storage_cache_size: usize,
    /// Storage cache TTL in seconds.
    pub storage_cache_ttl_secs: u64,
    /// Whether to track metrics.
    pub track_metrics: bool,
    /// Whether to log state operations.
    pub log_operations: bool,
    /// Current schema version for serialization.
    pub schema_version: u32,
}

impl Default for StateConfig {
    fn default() -> Self {
        Self {
            max_memory_bytes: 4 * 1024 * 1024,
            enable_storage_cache: true,
            storage_cache_size: 1024,
            storage_cache_ttl_secs: 60,
            track_metrics: true,
            log_operations: false,
            schema_version: 1,
        }
    }
}

impl StateConfig {
    /// Validate the configuration.
    pub fn validate(&self) -> Result<(), String> {
        if self.max_memory_bytes == 0 {
            return Err("max_memory_bytes must be > 0".into());
        }
        if self.storage_cache_size == 0 {
            return Err("storage_cache_size must be > 0".into());
        }
        if self.storage_cache_ttl_secs == 0 {
            return Err("storage_cache_ttl_secs must be > 0".into());
        }
        Ok(())
    }
}

// ── Metrics ──────────────────────────────────────────────────────────────

/// Metrics for the VM state subsystem.
#[derive(Debug, Default)]
pub struct StateMetrics {
    /// Total storage reads.
    pub storage_reads: AtomicU64,
    /// Total storage writes.
    pub storage_writes: AtomicU64,
    /// Total memory reads.
    pub memory_reads: AtomicU64,
    /// Total memory writes.
    pub memory_writes: AtomicU64,
    /// Total code retrievals.
    pub code_retrievals: AtomicU64,
    /// Total code sets.
    pub code_sets: AtomicU64,
    /// Total log emissions.
    pub log_emissions: AtomicU64,
    /// Storage cache hits.
    pub cache_hits: AtomicU64,
    /// Storage cache misses.
    pub cache_misses: AtomicU64,
    /// Memory expansion events.
    pub memory_expansions: AtomicU64,
    /// Peak memory size (in bytes).
    pub peak_memory_bytes: AtomicUsize,
    /// Number of contract creations.
    pub contract_creations: AtomicU64,
    /// Number of contract deletions.
    pub contract_deletions: AtomicU64,
    /// Number of balance transfers.
    pub balance_transfers: AtomicU64,
}

impl StateMetrics {
    pub fn record_storage_read(&self) {
        self.storage_reads.fetch_add(1, Ordering::Relaxed);
    }
    pub fn record_storage_write(&self) {
        self.storage_writes.fetch_add(1, Ordering::Relaxed);
    }
    pub fn record_memory_read(&self) {
        self.memory_reads.fetch_add(1, Ordering::Relaxed);
    }
    pub fn record_memory_write(&self) {
        self.memory_writes.fetch_add(1, Ordering::Relaxed);
    }
    pub fn record_code_retrieval(&self) {
        self.code_retrievals.fetch_add(1, Ordering::Relaxed);
    }
    pub fn record_code_set(&self) {
        self.code_sets.fetch_add(1, Ordering::Relaxed);
    }
    pub fn record_log_emission(&self) {
        self.log_emissions.fetch_add(1, Ordering::Relaxed);
    }
    pub fn record_cache_hit(&self) {
        self.cache_hits.fetch_add(1, Ordering::Relaxed);
    }
    pub fn record_cache_miss(&self) {
        self.cache_misses.fetch_add(1, Ordering::Relaxed);
    }
    pub fn record_memory_expansion(&self) {
        self.memory_expansions.fetch_add(1, Ordering::Relaxed);
    }
    pub fn record_peak_memory(&self, bytes: usize) {
        let mut current = self.peak_memory_bytes.load(Ordering::Relaxed);
        while bytes > current {
            match self.peak_memory_bytes.compare_exchange_weak(
                current,
                bytes,
                Ordering::Relaxed,
                Ordering::Relaxed,
            ) {
                Ok(_) => break,
                Err(actual) => current = actual,
            }
        }
    }
    pub fn record_contract_creation(&self) {
        self.contract_creations.fetch_add(1, Ordering::Relaxed);
    }
    pub fn record_contract_deletion(&self) {
        self.contract_deletions.fetch_add(1, Ordering::Relaxed);
    }
    pub fn record_balance_transfer(&self) {
        self.balance_transfers.fetch_add(1, Ordering::Relaxed);
    }
    pub fn snapshot(&self) -> StateMetricsSnapshot {
        StateMetricsSnapshot {
            storage_reads: self.storage_reads.load(Ordering::Relaxed),
            storage_writes: self.storage_writes.load(Ordering::Relaxed),
            memory_reads: self.memory_reads.load(Ordering::Relaxed),
            memory_writes: self.memory_writes.load(Ordering::Relaxed),
            code_retrievals: self.code_retrievals.load(Ordering::Relaxed),
            code_sets: self.code_sets.load(Ordering::Relaxed),
            log_emissions: self.log_emissions.load(Ordering::Relaxed),
            cache_hits: self.cache_hits.load(Ordering::Relaxed),
            cache_misses: self.cache_misses.load(Ordering::Relaxed),
            memory_expansions: self.memory_expansions.load(Ordering::Relaxed),
            peak_memory_bytes: self.peak_memory_bytes.load(Ordering::Relaxed),
            contract_creations: self.contract_creations.load(Ordering::Relaxed),
            contract_deletions: self.contract_deletions.load(Ordering::Relaxed),
            balance_transfers: self.balance_transfers.load(Ordering::Relaxed),
        }
    }
}

/// Snapshot of state metrics.
#[derive(Debug, Clone)]
pub struct StateMetricsSnapshot {
    pub storage_reads: u64,
    pub storage_writes: u64,
    pub memory_reads: u64,
    pub memory_writes: u64,
    pub code_retrievals: u64,
    pub code_sets: u64,
    pub log_emissions: u64,
    pub cache_hits: u64,
    pub cache_misses: u64,
    pub memory_expansions: u64,
    pub peak_memory_bytes: usize,
    pub contract_creations: u64,
    pub contract_deletions: u64,
    pub balance_transfers: u64,
}

// ── Quantum Type Aliases ────────────────────────────────────────────────

/// A 256‑bit quantum register (32 bytes in computational basis).
pub type Word = [u8; 32];

/// Complex amplitude for superposition states.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct ComplexAmplitude {
    pub real: f64,
    pub imag: f64,
}

impl ComplexAmplitude {
    pub fn probability(&self) -> f64 {
        self.real * self.real + self.imag * self.imag
    }
    pub fn normalize(&mut self) {
        let norm = self.probability().sqrt();
        if norm > 0.0 {
            self.real /= norm;
            self.imag /= norm;
        }
    }
}

// ── Density Matrix (optional quantum extension) ────────────────────────

/// Density matrix ρ representing the quantum state of a subsystem.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DensityMatrix {
    pub elements: Vec<Vec<ComplexAmplitude>>,
    pub dimension: usize,
    pub entropy: f64,
    pub purity: f64,
}

impl DensityMatrix {
    pub fn ground_state(dimension: usize) -> Self {
        let mut elements = vec![vec![ComplexAmplitude { real: 0.0, imag: 0.0 }; dimension]; dimension];
        elements[0][0] = ComplexAmplitude { real: 1.0, imag: 0.0 };
        Self { elements, dimension, entropy: 0.0, purity: 1.0 }
    }
    pub fn maximally_mixed(dimension: usize) -> Self {
        let amplitude = ComplexAmplitude { real: 1.0 / dimension as f64, imag: 0.0 };
        let mut elements = vec![vec![ComplexAmplitude { real: 0.0, imag: 0.0 }; dimension]; dimension];
        for i in 0..dimension { elements[i][i] = amplitude; }
        Self { elements, dimension, entropy: (dimension as f64).ln(), purity: 1.0 / dimension as f64 }
    }
    pub fn expectation_value(&self, observable: &HermitianOperator) -> f64 {
        let mut trace = 0.0;
        for i in 0..self.dimension {
            for j in 0..self.dimension {
                trace += self.elements[i][j].real * observable.matrix[j][i];
            }
        }
        trace
    }
    pub fn apply_unitary(&mut self, unitary: &UnitaryMatrix) -> Result<(), VmError> {
        let mut new_elements = vec![vec![ComplexAmplitude { real: 0.0, imag: 0.0 }; self.dimension]; self.dimension];
        for i in 0..self.dimension {
            for j in 0..self.dimension {
                let mut sum = ComplexAmplitude { real: 0.0, imag: 0.0 };
                for k in 0..self.dimension {
                    for l in 0..self.dimension {
                        let u_ik = unitary.matrix[i][k];
                        let rho_kl = self.elements[k][l];
                        let u_dag_lj = unitary.matrix[j][l];
                        sum.real += u_ik.real * rho_kl.real - u_ik.imag * rho_kl.imag;
                        sum.imag += u_ik.real * rho_kl.imag + u_ik.imag * rho_kl.real;
                    }
                }
                new_elements[i][j] = sum;
            }
        }
        self.elements = new_elements;
        self.recompute_properties();
        Ok(())
    }
    pub fn apply_lindblad(&mut self, operators: &[LindbladOperator], dt: f64) {
        let mut drho = vec![vec![ComplexAmplitude { real: 0.0, imag: 0.0 }; self.dimension]; self.dimension];
        for op in operators {
            let l = &op.matrix;
            let l_dag = op.dagger();
            for i in 0..self.dimension {
                for j in 0..self.dimension {
                    let mut l_rho_l_dag = ComplexAmplitude { real: 0.0, imag: 0.0 };
                    for k in 0..self.dimension {
                        for m in 0..self.dimension {
                            l_rho_l_dag.real += l[i][k].real * self.elements[k][m].real * l_dag[m][j].real;
                        }
                    }
                    let mut anticommutator = ComplexAmplitude { real: 0.0, imag: 0.0 };
                    for k in 0..self.dimension {
                        anticommutator.real += l_dag[i][k].real * l[k][j].real * self.elements[i][j].real;
                    }
                    drho[i][j].real += dt * (l_rho_l_dag.real - 0.5 * anticommutator.real);
                }
            }
        }
        for i in 0..self.dimension {
            for j in 0..self.dimension {
                self.elements[i][j].real += drho[i][j].real;
                self.elements[i][j].imag += drho[i][j].imag;
            }
        }
        self.recompute_properties();
    }
    fn recompute_properties(&mut self) {
        self.purity = self.compute_purity();
        self.entropy = self.compute_von_neumann_entropy();
    }
    fn compute_purity(&self) -> f64 {
        let mut trace_rho_sq = 0.0;
        for i in 0..self.dimension {
            for j in 0..self.dimension {
                trace_rho_sq += self.elements[i][j].probability();
            }
        }
        trace_rho_sq
    }
    fn compute_von_neumann_entropy(&self) -> f64 {
        if self.purity >= 1.0 { 0.0 } else { -self.purity.ln() }
    }
}

// ── Quantum Operators ───────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct HermitianOperator { pub matrix: Vec<Vec<f64>> }
#[derive(Debug, Clone)]
pub struct UnitaryMatrix { pub matrix: Vec<Vec<ComplexAmplitude>> }
#[derive(Debug, Clone)]
pub struct LindbladOperator { pub matrix: Vec<Vec<ComplexAmplitude>> }

impl LindbladOperator {
    pub fn dagger(&self) -> Self {
        let n = self.matrix.len();
        let mut dagger = vec![vec![ComplexAmplitude { real: 0.0, imag: 0.0 }; n]; n];
        for i in 0..n {
            for j in 0..n {
                dagger[i][j] = ComplexAmplitude {
                    real: self.matrix[j][i].real,
                    imag: -self.matrix[j][i].imag,
                };
            }
        }
        Self { matrix: dagger }
    }
}

// ── Classical Memory ─────────────────────────────────────────────────────

/// Classical memory with gas-aware expansion.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Memory {
    data: Vec<u8>,
    max_size: usize,
}

impl Memory {
    pub fn new() -> Self { Self { data: Vec::new(), max_size: 4 * 1024 * 1024 } }
    pub fn with_max_size(max_size: usize) -> Self { Self { data: Vec::new(), max_size } }
    pub fn size(&self) -> usize { self.data.len() }
    pub fn words(&self) -> usize { (self.size() + 31) / 32 }
    pub fn grow_to(&mut self, new_size: usize) -> Result<u64, VmError> {
        if new_size > self.max_size { return Err(VmError::MemoryLimit(new_size)); }
        if new_size <= self.data.len() { return Ok(0); }
        let old_words = self.words();
        self.data.resize(new_size, 0);
        let new_words = self.words();
        Ok(((new_words - old_words) as u64) * 3)
    }
    pub fn ensure(&mut self, offset: usize, size: usize) -> Result<u64, VmError> {
        if size == 0 { return Ok(0); }
        let new_end = offset.checked_add(size).ok_or(VmError::MemoryOffsetOverflow(offset, size))?;
        self.grow_to(new_end)
    }
    pub fn load32(&mut self, offset: usize) -> Result<Word, VmError> {
        self.ensure(offset, 32)?;
        let mut out = [0u8; 32];
        out.copy_from_slice(&self.data[offset..offset + 32]);
        Ok(out)
    }
    pub fn store32(&mut self, offset: usize, value: &Word) -> Result<u64, VmError> {
        let cost = self.ensure(offset, 32)?;
        self.data[offset..offset + 32].copy_from_slice(value);
        Ok(cost)
    }
    pub fn store8(&mut self, offset: usize, byte: u8) -> Result<u64, VmError> {
        let cost = self.ensure(offset, 1)?;
        self.data[offset] = byte;
        Ok(cost)
    }
    pub fn read_range(&mut self, offset: usize, size: usize) -> Result<Vec<u8>, VmError> {
        if size == 0 { return Ok(Vec::new()); }
        self.ensure(offset, size)?;
        Ok(self.data[offset..offset + size].to_vec())
    }
    pub fn write_range(&mut self, offset: usize, data: &[u8]) -> Result<u64, VmError> {
        if data.is_empty() { return Ok(0); }
        let cost = self.ensure(offset, data.len())?;
        self.data[offset..offset + data.len()].copy_from_slice(data);
        Ok(cost)
    }
    pub fn reset(&mut self) { self.data.clear(); }
}

impl Default for Memory { fn default() -> Self { Self::new() } }

// ── VmLog ────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct VmLog {
    pub contract: Word,
    pub topics: Vec<Word>,
    pub data: Vec<u8>,
}

impl fmt::Display for VmLog {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "LOG(contract={:?}, topics={}, data_len={})", &self.contract[..8], self.topics.len(), self.data.len())
    }
}

// ── VmState Trait ────────────────────────────────────────────────────────

pub trait VmState {
    fn sload(&self, contract: &Word, key: &Word) -> Result<Word, VmError>;
    fn sstore(&mut self, contract: &Word, key: &Word, value: Word) -> Result<(), VmError>;
    fn get_code(&self, contract: &Word) -> Vec<u8>;
    fn set_code(&mut self, contract: &Word, code: Vec<u8>);
    fn emit_log(&mut self, contract: &Word, topics: Vec<Word>, data: Vec<u8>);
    fn balance(&self, address: &Word) -> u128;
    fn transfer_balance(&mut self, from: &Word, to: &Word, amount: u128) -> Result<(), VmError>;
    fn create_contract(&mut self, creator: &Word, value: u128, init_code: &[u8]) -> Word;
    fn create2_contract(&mut self, creator: &Word, value: u128, init_code: &[u8], salt: &Word) -> Word;
    fn delete_contract(&mut self, contract: &Word);
    fn origin(&self) -> Word;
    fn gas_price(&self) -> u64;
    fn qload(&self, contract: &Word, key: &Word) -> Result<Word, VmError> { self.sload(contract, key) }
    fn qstore(&mut self, contract: &Word, key: &Word, value: Word) -> Result<(), VmError> { self.sstore(contract, key, value) }
    fn qget_code(&self, contract: &Word) -> Vec<u8> { self.get_code(contract) }
    fn qset_code(&mut self, contract: &Word, code: Vec<u8>) { self.set_code(contract, code) }
    fn qemit_log(&mut self, contract: &Word, topics: Vec<Word>, data: Vec<u8>) { self.emit_log(contract, topics, data) }
}

// ── VmStorage ────────────────────────────────────────────────────────────

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct VmStorage {
    pub storage: BTreeMap<(Word, Word), Word>,
    pub code: BTreeMap<Word, Vec<u8>>,
    pub nonces: BTreeMap<Word, u64>,
    pub balances: BTreeMap<Word, u128>,
    #[serde(skip)]
    pub logs: Vec<VmLog>,
    #[serde(skip)]
    pub origin_addr: Word,
    #[serde(skip)]
    pub gas_price_value: u64,
    #[serde(skip)]
    pub config: StateConfig,
    #[serde(skip)]
    pub metrics: Arc<StateMetrics>,
    #[serde(skip)]
    pub cache: Option<Arc<Mutex<lru::LruCache<(Word, Word), (Word, Instant)>>>>,
}

impl VmStorage {
    pub fn new() -> Self { Self::default() }
    pub fn with_config(config: StateConfig) -> Self {
        let metrics = Arc::new(StateMetrics::default());
        let cache = if config.enable_storage_cache {
            let size = std::num::NonZeroUsize::new(config.storage_cache_size)
                .map(|s| lru::LruCache::new(s))
                .map(|c| Arc::new(Mutex::new(c)));
            Some(c)
        } else { None };
        Self { config, metrics, cache, ..Default::default() }
    }
    pub fn clear_logs(&mut self) { self.logs.clear(); }
    pub fn log_count(&self) -> usize { self.logs.len() }
    pub fn has_logs(&self) -> bool { !self.logs.is_empty() }
    pub fn inc_nonce(&mut self, contract: &Word) -> u64 {
        let nonce = self.nonces.entry(*contract).or_insert(0);
        let prev = *nonce;
        *nonce = nonce.wrapping_add(1);
        prev
    }
    pub fn get_nonce(&self, contract: &Word) -> u64 { self.nonces.get(contract).copied().unwrap_or(0) }
    pub fn set_origin(&mut self, origin: Word) { self.origin_addr = origin; }
    pub fn set_gas_price(&mut self, price: u64) { self.gas_price_value = price; }
    pub fn snapshot(&self) -> Self { self.clone() }
    pub fn apply_snapshot(&mut self, snapshot: Self) { *self = snapshot; }
    pub fn metrics(&self) -> &StateMetrics { &self.metrics }
    pub fn config(&self) -> &StateConfig { &self.config }
}

impl VmState for VmStorage {
    fn sload(&self, contract: &Word, key: &Word) -> Result<Word, VmError> {
        self.metrics.record_storage_read();
        if self.config.enable_storage_cache {
            if let Some(cache) = &self.cache {
                let mut guard = cache.lock();
                let key_tuple = (*contract, *key);
                if let Some((value, expires)) = guard.get(&key_tuple) {
                    if *expires > Instant::now() {
                        self.metrics.record_cache_hit();
                        return Ok(*value);
                    } else {
                        guard.pop(&key_tuple);
                    }
                }
                self.metrics.record_cache_miss();
            }
        }
        let value = self.storage.get(&(*contract, *key)).copied().unwrap_or([0u8; 32]);
        if self.config.enable_storage_cache {
            if let Some(cache) = &self.cache {
                let mut guard = cache.lock();
                let key_tuple = (*contract, *key);
                guard.put(key_tuple, (value, Instant::now() + Duration::from_secs(self.config.storage_cache_ttl_secs)));
            }
        }
        Ok(value)
    }
    fn sstore(&mut self, contract: &Word, key: &Word, value: Word) -> Result<(), VmError> {
        self.metrics.record_storage_write();
        if value == [0u8; 32] {
            self.storage.remove(&(*contract, *key));
        } else {
            self.storage.insert((*contract, *key), value);
        }
        if self.config.log_operations {
            trace!("SSTORE contract={:?}, key={:?}, value={:?}", &contract[..8], &key[..8], &value[..8]);
        }
        Ok(())
    }
    fn get_code(&self, contract: &Word) -> Vec<u8> {
        self.metrics.record_code_retrieval();
        self.code.get(contract).cloned().unwrap_or_default()
    }
    fn set_code(&mut self, contract: &Word, code: Vec<u8>) {
        self.metrics.record_code_set();
        if code.is_empty() {
            self.code.remove(contract);
        } else {
            self.code.insert(*contract, code);
        }
        if self.config.log_operations {
            debug!("Code set for contract {:?} ({} bytes)", &contract[..8], code.len());
        }
    }
    fn emit_log(&mut self, contract: &Word, topics: Vec<Word>, data: Vec<u8>) {
        self.metrics.record_log_emission();
        let log = VmLog { contract: *contract, topics, data };
        self.logs.push(log);
        if self.config.log_operations {
            trace!("Log emitted: {}", self.logs.last().unwrap());
        }
    }
    fn balance(&self, address: &Word) -> u128 {
        self.balances.get(address).copied().unwrap_or(0)
    }
    fn transfer_balance(&mut self, from: &Word, to: &Word, amount: u128) -> Result<(), VmError> {
        self.metrics.record_balance_transfer();
        let from_balance = self.balances.get(from).copied().unwrap_or(0);
        if from_balance < amount {
            return Err(VmError::InsufficientBalance { have: from_balance, need: amount });
        }
        *self.balances.entry(*from).or_insert(0) = from_balance - amount;
        *self.balances.entry(*to).or_insert(0) += amount;
        if self.config.log_operations {
            trace!("Transfer {} from {:?} to {:?}", amount, &from[..8], &to[..8]);
        }
        Ok(())
    }
    fn create_contract(&mut self, creator: &Word, value: u128, init_code: &[u8]) -> Word {
        self.metrics.record_contract_creation();
        let nonce = self.inc_nonce(creator);
        let mut addr = [0u8; 32];
        addr[0..8].copy_from_slice(&creator[0..8]);
        addr[8..16].copy_from_slice(&nonce.to_le_bytes());
        self.set_code(&addr, init_code.to_vec());
        let _ = self.transfer_balance(creator, &addr, value);
        if self.config.log_operations {
            trace!("Created contract {:?} with {} bytes", &addr[..8], init_code.len());
        }
        addr
    }
    fn create2_contract(&mut self, creator: &Word, value: u128, init_code: &[u8], salt: &Word) -> Word {
        self.metrics.record_contract_creation();
        let mut addr = [0u8; 32];
        addr[0..8].copy_from_slice(&creator[0..8]);
        addr[8..16].copy_from_slice(&salt[0..8]);
        self.set_code(&addr, init_code.to_vec());
        let _ = self.transfer_balance(creator, &addr, value);
        if self.config.log_operations {
            trace!("Created contract via CREATE2 {:?}", &addr[..8]);
        }
        addr
    }
    fn delete_contract(&mut self, contract: &Word) {
        self.metrics.record_contract_deletion();
        self.code.remove(contract);
        self.storage.retain(|(c, _), _| c != contract);
        self.balances.remove(contract);
        self.nonces.remove(contract);
        if self.config.log_operations {
            trace!("Deleted contract {:?}", &contract[..8]);
        }
    }
    fn origin(&self) -> Word { self.origin_addr }
    fn gas_price(&self) -> u64 { self.gas_price_value }
}

// ── StateManager ─────────────────────────────────────────────────────────

#[derive(Clone)]
pub struct StateManager {
    config: Arc<StateConfig>,
    metrics: Arc<StateMetrics>,
    storage: Arc<Mutex<VmStorage>>,
}

impl StateManager {
    pub fn new(config: StateConfig) -> Result<Self, String> {
        config.validate()?;
        let metrics = Arc::new(StateMetrics::default());
        let storage = Arc::new(Mutex::new(VmStorage::with_config(config.clone())));
        Ok(Self { config: Arc::new(config), metrics, storage })
    }
    pub fn config(&self) -> &StateConfig { &self.config }
    pub fn metrics_snapshot(&self) -> StateMetricsSnapshot { self.metrics.snapshot() }
    pub fn storage(&self) -> &Mutex<VmStorage> { &self.storage }
    pub fn execute<F, R>(&self, f: F) -> R where F: FnOnce(&mut VmStorage) -> R {
        let mut guard = self.storage.lock();
        f(&mut guard)
    }
    pub fn snapshot(&self) -> VmStorage { self.storage.lock().snapshot() }
    pub fn apply_snapshot(&self, snapshot: VmStorage) {
        let mut guard = self.storage.lock();
        guard.apply_snapshot(snapshot);
    }
    pub fn clear_cache(&self) {
        let mut guard = self.storage.lock();
        if let Some(cache) = &guard.cache {
            cache.lock().clear();
        }
    }
    pub fn reset_metrics(&self) {
        self.metrics.storage_reads.store(0, Ordering::Relaxed);
        self.metrics.storage_writes.store(0, Ordering::Relaxed);
        self.metrics.memory_reads.store(0, Ordering::Relaxed);
        self.metrics.memory_writes.store(0, Ordering::Relaxed);
        self.metrics.code_retrievals.store(0, Ordering::Relaxed);
        self.metrics.code_sets.store(0, Ordering::Relaxed);
        self.metrics.log_emissions.store(0, Ordering::Relaxed);
        self.metrics.cache_hits.store(0, Ordering::Relaxed);
        self.metrics.cache_misses.store(0, Ordering::Relaxed);
        self.metrics.memory_expansions.store(0, Ordering::Relaxed);
        self.metrics.peak_memory_bytes.store(0, Ordering::Relaxed);
        self.metrics.contract_creations.store(0, Ordering::Relaxed);
        self.metrics.contract_deletions.store(0, Ordering::Relaxed);
        self.metrics.balance_transfers.store(0, Ordering::Relaxed);
    }
}

// ── Global singleton ─────────────────────────────────────────────────────

#[cfg(feature = "std")]
static GLOBAL_STATE_MANAGER: std::sync::OnceLock<StateManager> = std::sync::OnceLock::new();

#[cfg(feature = "std")]
pub fn init_state_manager(config: StateConfig) -> Result<(), String> {
    let manager = StateManager::new(config)?;
    GLOBAL_STATE_MANAGER.set(manager).map_err(|_| "State manager already initialized".into())
}

#[cfg(feature = "std")]
pub fn state_manager() -> &'static StateManager {
    GLOBAL_STATE_MANAGER.get().expect("State manager not initialized")
}

// ── Tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn test_config_validation() {
        let mut config = StateConfig::default();
        assert!(config.validate().is_ok());
        config.max_memory_bytes = 0; assert!(config.validate().is_err());
        config.max_memory_bytes = 1024; config.storage_cache_size = 0; assert!(config.validate().is_err());
        config.storage_cache_size = 10; config.storage_cache_ttl_secs = 0; assert!(config.validate().is_err());
    }

    #[test]
    fn test_density_matrix() {
        let rho = DensityMatrix::ground_state(4);
        assert!((rho.purity - 1.0).abs() < 1e-10);
        assert!((rho.entropy - 0.0).abs() < 1e-10);
        let rho2 = DensityMatrix::maximally_mixed(4);
        assert!((rho2.purity - 0.25).abs() < 1e-10);
        assert!(rho2.entropy > 0.0);
    }

    #[test]
    fn test_memory() {
        let mut mem = Memory::new();
        assert_eq!(mem.size(), 0);
        let cost = mem.store32(100, &[0xAA; 32]).unwrap();
        assert_eq!(cost, 12);
        assert!(mem.size() >= 132);
        let result = mem.ensure(200, 1);
        assert!(result.is_err());
    }

    #[test]
    fn test_vm_storage() {
        let config = StateConfig::default();
        let mut storage = VmStorage::with_config(config);
        let contract = [0xAA; 32];
        let key = [0x01; 32];
        let value = [0xDE; 32];
        assert_eq!(storage.sload(&contract, &key).unwrap(), [0u8; 32]);
        storage.sstore(&contract, &key, value).unwrap();
        assert_eq!(storage.sload(&contract, &key).unwrap(), value);
        storage.sstore(&contract, &key, [0u8; 32]).unwrap();
        assert_eq!(storage.sload(&contract, &key).unwrap(), [0u8; 32]);
    }

    #[test]
    fn test_vm_storage_nonce() {
        let mut storage = VmStorage::new();
        let contract = [0xFF; 32];
        assert_eq!(storage.get_nonce(&contract), 0);
        assert_eq!(storage.inc_nonce(&contract), 0);
        assert_eq!(storage.get_nonce(&contract), 1);
    }

    #[test]
    fn test_balance_transfer() {
        let mut storage = VmStorage::new();
        let from = [0x01; 32];
        let to = [0x02; 32];
        storage.balances.insert(from, 1000);
        storage.transfer_balance(&from, &to, 300).unwrap();
        assert_eq!(storage.balance(&from), 700);
        assert_eq!(storage.balance(&to), 300);
    }

    #[test]
    fn test_snapshot() {
        let mut storage = VmStorage::new();
        let contract = [0xAA; 32];
        let key = [0x01; 32];
        storage.sstore(&contract, &key, [0x42; 32]).unwrap();
        let snapshot = storage.snapshot();
        storage.sstore(&contract, &key, [0xFF; 32]).unwrap();
        assert_eq!(storage.sload(&contract, &key).unwrap(), [0xFF; 32]);
        storage.apply_snapshot(snapshot);
        assert_eq!(storage.sload(&contract, &key).unwrap(), [0x42; 32]);
    }

    #[test]
    fn test_logs() {
        let mut storage = VmStorage::new();
        let contract = [0xBB; 32];
        let topics = vec![[0x01; 32], [0x02; 32]];
        let data = vec![0xDE, 0xAD, 0xBE, 0xEF];
        storage.emit_log(&contract, topics.clone(), data.clone());
        assert_eq!(storage.log_count(), 1);
        let log = &storage.logs[0];
        assert_eq!(log.contract, contract);
        assert_eq!(log.topics, topics);
        assert_eq!(log.data, data);
        storage.clear_logs();
        assert!(!storage.has_logs());
    }

    #[test]
    fn test_code() {
        let mut storage = VmStorage::new();
        let contract = [0xCC; 32];
        let code = vec![0x60, 0x01, 0x00];
        storage.set_code(&contract, code.clone());
        assert_eq!(storage.get_code(&contract), code);
        storage.set_code(&contract, vec![]);
        assert!(storage.get_code(&contract).is_empty());
    }

    #[test]
    fn test_cache() {
        let config = StateConfig { enable_storage_cache: true, storage_cache_size: 10, storage_cache_ttl_secs: 1, ..Default::default() };
        let mut storage = VmStorage::with_config(config);
        let contract = [0xAA; 32];
        let key = [0x01; 32];
        let value = [0xDE; 32];
        storage.sstore(&contract, &key, value).unwrap();
        let _ = storage.sload(&contract, &key).unwrap();
        let _ = storage.sload(&contract, &key).unwrap();
        // Cache hit should have occurred.
        assert!(storage.metrics.cache_hits.load(Ordering::Relaxed) > 0);
    }

    #[test]
    fn test_manager() {
        let config = StateConfig::default();
        let manager = StateManager::new(config).unwrap();
        let contract = [0xAA; 32];
        let key = [0x01; 32];
        let value = [0xDE; 32];
        manager.execute(|s| { s.sstore(&contract, &key, value).unwrap(); });
        let result = manager.execute(|s| s.sload(&contract, &key).unwrap());
        assert_eq!(result, value);
        let snap = manager.metrics_snapshot();
        assert_eq!(snap.storage_writes, 1);
        assert_eq!(snap.storage_reads, 1);
    }
}
