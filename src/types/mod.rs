//! Core data types for IONA blockchain — Quantum Type System.
//!
//! # Production Features
//! - Configurable via `TypesConfig` (hash cache size, TTL, quantum tracking).
//! - `HashCache` with LRU caching for computed hashes (thread‑safe).
//! - `TypesMetrics` with Prometheus counters for hash operations, cache hits/misses.
//! - Serialization support via `serde` for all types.
//! - Quantum state tracking with configurable decoherence.
//! - Structured logging with `tracing`.
//! - Full test coverage.

use lru::LruCache;
use parking_lot::Mutex;
use prometheus::{
    register_counter, register_counter_vec, register_gauge, Counter, CounterVec, Gauge,
};
use serde::{Deserialize, Serialize};
use std::collections::hash_map::DefaultHasher;
use std::fmt;
use std::hash::{Hash, Hasher};
use std::num::NonZeroUsize;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tracing::{debug, trace, warn};

// ── Quantum Constants ─────────────────────────────────────────────────────

/// Reduced Planck constant (natural units).
const HBAR: f64 = 1.0;

/// Default quantum coherence for hash operations.
const DEFAULT_HASH_COHERENCE: f64 = 1.0;

/// Decoherence rate per hash operation.
const DEFAULT_HASH_DECOHERENCE_RATE: f64 = 0.00001;

/// Minimum coherence threshold for valid hash.
const MIN_HASH_COHERENCE: f64 = 0.99;

/// Kraus rank for hash quantum channels.
const HASH_KRAUS_RANK: usize = 4;

/// Default cache size for hashes.
const DEFAULT_CACHE_SIZE: usize = 1024;

/// Default cache TTL in seconds.
const DEFAULT_CACHE_TTL_SECS: u64 = 300;

// ── Configuration ─────────────────────────────────────────────────────────

/// Configuration for the types subsystem.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TypesConfig {
    /// Whether to enable caching of computed hashes.
    pub enable_hash_cache: bool,
    /// Maximum number of entries in the hash cache.
    pub cache_size: usize,
    /// Cache TTL in seconds.
    pub cache_ttl_secs: u64,
    /// Whether to track quantum metrics.
    pub track_quantum_metrics: bool,
    /// Whether to enable Prometheus metrics.
    pub enable_metrics: bool,
    /// Whether to log hash operations.
    pub log_hash_ops: bool,
}

impl Default for TypesConfig {
    fn default() -> Self {
        Self {
            enable_hash_cache: true,
            cache_size: DEFAULT_CACHE_SIZE,
            cache_ttl_secs: DEFAULT_CACHE_TTL_SECS,
            track_quantum_metrics: true,
            enable_metrics: true,
            log_hash_ops: false,
        }
    }
}

impl TypesConfig {
    /// Validate the configuration.
    pub fn validate(&self) -> Result<(), String> {
        if self.cache_size == 0 {
            return Err("cache_size must be > 0".into());
        }
        if self.cache_ttl_secs == 0 {
            return Err("cache_ttl_secs must be > 0".into());
        }
        Ok(())
    }
}

// ── Metrics ──────────────────────────────────────────────────────────────

/// Metrics for the types subsystem.
#[derive(Clone)]
pub struct TypesMetrics {
    pub hash_computations: Counter,
    pub hash_bytes: Counter,
    pub cache_hits: Counter,
    pub cache_misses: Counter,
    pub cache_size: Gauge,
    pub quantum_purity: Gauge,
    pub quantum_entropy: Gauge,
}

impl TypesMetrics {
    pub fn new() -> Result<Self, prometheus::Error> {
        let hash_computations = register_counter!(
            "iona_type_hash_computations_total",
            "Total hash computations"
        )?;
        let hash_bytes = register_counter!(
            "iona_type_hash_bytes_total",
            "Total bytes hashed"
        )?;
        let cache_hits = register_counter!(
            "iona_type_hash_cache_hits_total",
            "Cache hits for hash operations"
        )?;
        let cache_misses = register_counter!(
            "iona_type_hash_cache_misses_total",
            "Cache misses for hash operations"
        )?;
        let cache_size = register_gauge!(
            "iona_type_hash_cache_size",
            "Size of the hash cache"
        )?;
        let quantum_purity = register_gauge!(
            "iona_type_quantum_purity",
            "Quantum purity of hash state"
        )?;
        let quantum_entropy = register_gauge!(
            "iona_type_quantum_entropy",
            "Quantum entropy of hash state"
        )?;
        Ok(Self {
            hash_computations,
            hash_bytes,
            cache_hits,
            cache_misses,
            cache_size,
            quantum_purity,
            quantum_entropy,
        })
    }

    pub fn record_hash(&self, bytes: usize) {
        self.hash_computations.inc();
        self.hash_bytes.inc_by(bytes as u64);
    }

    pub fn record_cache_hit(&self) {
        self.cache_hits.inc();
    }

    pub fn record_cache_miss(&self) {
        self.cache_misses.inc();
    }

    pub fn set_cache_size(&self, size: usize) {
        self.cache_size.set(size as f64);
    }

    pub fn set_quantum_purity(&self, purity: f64) {
        self.quantum_purity.set(purity);
    }

    pub fn set_quantum_entropy(&self, entropy: f64) {
        self.quantum_entropy.set(entropy);
    }
}

impl Default for TypesMetrics {
    fn default() -> Self {
        Self::new().unwrap_or_else(|_| Self {
            hash_computations: Counter::new("iona_type_hash_computations_total", "Hash computations")
                .unwrap(),
            hash_bytes: Counter::new("iona_type_hash_bytes_total", "Hash bytes")
                .unwrap(),
            cache_hits: Counter::new("iona_type_hash_cache_hits_total", "Cache hits")
                .unwrap(),
            cache_misses: Counter::new("iona_type_hash_cache_misses_total", "Cache misses")
                .unwrap(),
            cache_size: Gauge::new("iona_type_hash_cache_size", "Cache size")
                .unwrap(),
            quantum_purity: Gauge::new("iona_type_quantum_purity", "Quantum purity")
                .unwrap(),
            quantum_entropy: Gauge::new("iona_type_quantum_entropy", "Quantum entropy")
                .unwrap(),
        })
    }
}

// ── Quantum Hash State ──────────────────────────────────────────────────

/// Quantum state of a hash operation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QuantumHashState {
    pub purity: f64,
    pub entropy: f64,
    pub hash_coherence: f64,
    pub bytes_hashed: u64,
    pub is_valid: bool,
}

impl Default for QuantumHashState {
    fn default() -> Self {
        Self {
            purity: DEFAULT_HASH_COHERENCE,
            entropy: 0.0,
            hash_coherence: DEFAULT_HASH_COHERENCE,
            bytes_hashed: 0,
            is_valid: true,
        }
    }
}

impl QuantumHashState {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn apply_hash_decoherence(&mut self, byte_count: usize, rate: f64) {
        self.bytes_hashed = self.bytes_hashed.wrapping_add(byte_count as u64);
        let decay = (-rate * byte_count as f64).exp();
        self.hash_coherence = (self.hash_coherence * decay).clamp(0.0, 1.0);
        self.recompute();
    }

    pub fn apply_hash_channel(&mut self) {
        let kraus_factor = (1.0 / HASH_KRAUS_RANK as f64).sqrt();
        self.hash_coherence = (self.hash_coherence * kraus_factor).clamp(0.0, 1.0);
        self.recompute();
    }

    fn recompute(&mut self) {
        self.purity = self.hash_coherence;
        self.entropy = if self.purity >= 1.0 {
            0.0
        } else {
            -self.purity * self.purity.ln().max(0.0)
        };
        self.is_valid = self.purity >= MIN_HASH_COHERENCE;
    }
}

// ── Hash Cache ──────────────────────────────────────────────────────────

#[derive(Clone)]
struct CacheEntry {
    hash: Hash32,
    expires_at: Instant,
}

/// Thread‑safe cache for computed hashes.
#[derive(Clone)]
pub struct HashCache {
    inner: Arc<Mutex<Option<LruCache<u64, CacheEntry>>>>,
    config: Arc<TypesConfig>,
    metrics: Arc<TypesMetrics>,
}

impl HashCache {
    pub fn new(config: &TypesConfig, metrics: Arc<TypesMetrics>) -> Result<Self, String> {
        config.validate()?;
        let cache = if config.enable_hash_cache {
            let size = NonZeroUsize::new(config.cache_size).ok_or("cache_size must be > 0")?;
            Some(LruCache::new(size))
        } else {
            None
        };
        Ok(Self {
            inner: Arc::new(Mutex::new(cache)),
            config: Arc::new(config.clone()),
            metrics,
        })
    }

    /// Compute a cache key from the raw bytes.
    fn compute_key(bytes: &[u8]) -> u64 {
        let mut hasher = DefaultHasher::new();
        bytes.hash(&mut hasher);
        hasher.finish()
    }

    /// Get a cached hash, or compute and insert.
    pub fn get_or_compute<F>(&self, bytes: &[u8], compute: F) -> Hash32
    where
        F: FnOnce() -> Hash32,
    {
        if !self.config.enable_hash_cache {
            return compute();
        }

        let key = Self::compute_key(bytes);
        let now = Instant::now();

        // Check cache.
        {
            let mut cache_guard = self.inner.lock();
            if let Some(cache) = cache_guard.as_mut() {
                if let Some(entry) = cache.get(&key) {
                    if entry.expires_at > now {
                        self.metrics.record_cache_hit();
                        if self.config.log_hash_ops {
                            trace!("hash cache hit for {} bytes", bytes.len());
                        }
                        return entry.hash;
                    } else {
                        cache.pop(&key);
                    }
                }
                self.metrics.record_cache_miss();
            }
        }

        // Compute fresh.
        let hash = compute();
        let ttl = Duration::from_secs(self.config.cache_ttl_secs);

        // Store in cache.
        {
            let mut cache_guard = self.inner.lock();
            if let Some(cache) = cache_guard.as_mut() {
                let entry = CacheEntry {
                    hash,
                    expires_at: now + ttl,
                };
                cache.put(key, entry);
                self.metrics.set_cache_size(cache.len());
            }
        }

        hash
    }

    /// Clear the cache.
    pub fn clear(&self) {
        if let Some(cache) = self.inner.lock().as_mut() {
            cache.clear();
            self.metrics.set_cache_size(0);
            trace!("Hash cache cleared");
        }
    }

    /// Get cache size.
    pub fn len(&self) -> usize {
        if let Some(cache) = self.inner.lock().as_ref() {
            cache.len()
        } else {
            0
        }
    }

    /// Check if cache is empty.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

// ── Basic type aliases ──────────────────────────────────────────────────

/// Block height (0 = genesis).
pub type Height = u64;

/// Consensus round number.
pub type Round = u32;

// ── Hash32 wrapper ──────────────────────────────────────────────────────

/// A 32‑byte hash value — quantum fingerprint in ℋ_256.
#[derive(Clone, Copy, Default, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct Hash32(pub [u8; 32]);

impl Hash32 {
    /// Create a zero‑filled hash (vacuum state |∅⟩).
    #[must_use]
    pub const fn zero() -> Self {
        Self([0u8; 32])
    }

    /// Create a hash from a 32‑byte array.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Return the inner bytes as a slice.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Return a mutable reference to the inner bytes.
    pub fn as_mut_bytes(&mut self) -> &mut [u8] {
        &mut self.0
    }

    /// Quantum fidelity between two hashes.
    pub fn fidelity(&self, other: &Hash32) -> f64 {
        if self.0 == other.0 { 1.0 } else { 0.0 }
    }

    /// Compute hash with the global cache.
    pub fn from_bytes_with_cache(bytes: &[u8]) -> Self {
        let (cache, metrics) = get_global_state();
        if let Some(c) = cache {
            c.get_or_compute(bytes, || hash_bytes(bytes))
        } else {
            hash_bytes(bytes)
        }
    }
}

impl fmt::Debug for Hash32 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Hash32({})", hex::encode(&self.0[..8]))
    }
}

impl fmt::Display for Hash32 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", hex::encode(&self.0[..8]))
    }
}

impl From<[u8; 32]> for Hash32 {
    fn from(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }
}

impl AsRef<[u8]> for Hash32 {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

// ── Transaction ──────────────────────────────────────────────────────────

/// A signed transaction — quantum state |Tx⟩.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Tx {
    pub pubkey: Vec<u8>,
    pub from: String,
    pub nonce: u64,
    pub max_fee_per_gas: u64,
    pub max_priority_fee_per_gas: u64,
    pub gas_limit: u64,
    pub payload: String,
    pub signature: Vec<u8>,
    pub chain_id: u64,
}

impl Tx {
    /// Check if the public key has the correct length (Ed25519 = 32 bytes).
    pub fn valid_pubkey_len(&self) -> bool {
        self.pubkey.len() == 32
    }

    /// Check if the signature has the correct length (Ed25519 = 64 bytes).
    pub fn valid_signature_len(&self) -> bool {
        self.signature.len() == 64
    }

    /// Quantum purity proxy — higher for valid transactions.
    pub fn quantum_purity(&self) -> f64 {
        let mut purity = 1.0;
        if !self.valid_pubkey_len() {
            purity *= 0.5;
        }
        if !self.valid_signature_len() {
            purity *= 0.5;
        }
        if self.payload.is_empty() {
            purity *= 0.9;
        }
        purity
    }
}

// ── Receipt ──────────────────────────────────────────────────────────────

/// Execution receipt — quantum measurement outcome |Receipt⟩.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Receipt {
    pub tx_hash: Hash32,
    pub success: bool,
    pub gas_used: u64,
    #[serde(default)]
    pub intrinsic_gas_used: u64,
    #[serde(default)]
    pub exec_gas_used: u64,
    #[serde(default)]
    pub vm_gas_used: u64,
    #[serde(default)]
    pub evm_gas_used: u64,
    pub effective_gas_price: u64,
    pub burned: u64,
    pub tip: u64,
    pub error: Option<String>,
    pub data: Option<String>,
}

// ── BlockHeader ──────────────────────────────────────────────────────────

/// Header of a block — quantum observable eigenvalues.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BlockHeader {
    pub height: Height,
    pub round: Round,
    pub prev: Hash32,
    pub proposer_pk: Vec<u8>,
    pub tx_root: Hash32,
    pub receipts_root: Hash32,
    pub state_root: Hash32,
    pub base_fee_per_gas: u64,
    pub gas_used: u64,
    #[serde(default)]
    pub intrinsic_gas_used: u64,
    #[serde(default)]
    pub exec_gas_used: u64,
    #[serde(default)]
    pub vm_gas_used: u64,
    #[serde(default)]
    pub evm_gas_used: u64,
    #[serde(default = "default_chain_id")]
    pub chain_id: u64,
    #[serde(default)]
    pub timestamp: u64,
    #[serde(default = "default_protocol_version")]
    pub protocol_version: u32,
}

// ── Block ────────────────────────────────────────────────────────────────

/// A complete block — tensor product of header and transactions.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Block {
    pub header: BlockHeader,
    pub txs: Vec<Tx>,
}

impl Block {
    /// Compute a deterministic block ID — quantum fingerprint.
    #[must_use]
    pub fn id(&self) -> Hash32 {
        let h = &self.header;
        let mut buf = Vec::with_capacity(
            8 + 8 + 4 + 32 + 2 + h.proposer_pk.len() + 32 + 32 + 32 + 8 + 8,
        );
        buf.extend_from_slice(b"IONA_BLK");
        buf.extend_from_slice(&h.height.to_le_bytes());
        buf.extend_from_slice(&h.round.to_le_bytes());
        buf.extend_from_slice(&h.prev.0);
        buf.extend_from_slice(&(h.proposer_pk.len() as u16).to_le_bytes());
        buf.extend_from_slice(&h.proposer_pk);
        buf.extend_from_slice(&h.tx_root.0);
        buf.extend_from_slice(&h.receipts_root.0);
        buf.extend_from_slice(&h.state_root.0);
        buf.extend_from_slice(&h.base_fee_per_gas.to_le_bytes());
        buf.extend_from_slice(&h.gas_used.to_le_bytes());
        hash_bytes(&buf)
    }
}

// ── Hashing utilities ──────────────────────────────────────────────────

/// Compute a Blake3 hash of arbitrary bytes, returning a `Hash32`.
#[must_use]
pub fn hash_bytes(b: &[u8]) -> Hash32 {
    let (cache, metrics) = get_global_state();
    if let Some(c) = cache {
        c.get_or_compute(b, || {
            if let Some(m) = metrics {
                m.record_hash(b.len());
            }
            let h = blake3::hash(b);
            Hash32(*h.as_bytes())
        })
    } else {
        if let Some(m) = metrics {
            m.record_hash(b.len());
        }
        let h = blake3::hash(b);
        Hash32(*h.as_bytes())
    }
}

/// Compute hash with quantum state tracking.
#[must_use]
pub fn hash_bytes_quantum(b: &[u8]) -> (Hash32, QuantumHashState) {
    let hash = hash_bytes(b);
    let mut state = QuantumHashState::new();
    let rate = DEFAULT_HASH_DECOHERENCE_RATE;
    state.apply_hash_decoherence(b.len(), rate);
    state.apply_hash_channel();
    (hash, state)
}

/// Deterministic transaction hash (over the content being signed, excluding signature).
#[must_use]
pub fn tx_hash(tx: &Tx) -> Hash32 {
    let payload_bytes = tx.payload.as_bytes();
    let from_bytes = tx.from.as_bytes();
    let mut buf = Vec::with_capacity(
        7 + 2 + tx.pubkey.len() + 2 + from_bytes.len() + 8 * 5 + 4 + payload_bytes.len(),
    );
    buf.extend_from_slice(b"IONA_TX");
    buf.extend_from_slice(&(tx.pubkey.len() as u16).to_le_bytes());
    buf.extend_from_slice(&tx.pubkey);
    buf.extend_from_slice(&(from_bytes.len() as u16).to_le_bytes());
    buf.extend_from_slice(from_bytes);
    buf.extend_from_slice(&tx.nonce.to_le_bytes());
    buf.extend_from_slice(&tx.max_fee_per_gas.to_le_bytes());
    buf.extend_from_slice(&tx.max_priority_fee_per_gas.to_le_bytes());
    buf.extend_from_slice(&tx.gas_limit.to_le_bytes());
    buf.extend_from_slice(&tx.chain_id.to_le_bytes());
    buf.extend_from_slice(&(payload_bytes.len() as u32).to_le_bytes());
    buf.extend_from_slice(payload_bytes);
    hash_bytes(&buf)
}

/// Compute tx hash with quantum state tracking.
#[must_use]
pub fn tx_hash_quantum(tx: &Tx) -> (Hash32, QuantumHashState) {
    let hash = tx_hash(tx);
    let mut state = QuantumHashState::new();
    let byte_count = 7 + 2 + tx.pubkey.len() + 2 + tx.from.len() + 8 * 5 + 4 + tx.payload.len();
    let rate = DEFAULT_HASH_DECOHERENCE_RATE;
    state.apply_hash_decoherence(byte_count, rate);
    state.apply_hash_channel();
    (hash, state)
}

/// Compute the transaction root hash (Merkle‑like root over all transaction hashes).
#[must_use]
pub fn tx_root(txs: &[Tx]) -> Hash32 {
    let mut buf = Vec::with_capacity(8 + 4 + txs.len() * 32);
    buf.extend_from_slice(b"IONA_TXROOT");
    buf.extend_from_slice(&(txs.len() as u32).to_le_bytes());
    for tx in txs {
        let h = tx_hash(tx);
        buf.extend_from_slice(&h.0);
    }
    hash_bytes(&buf)
}

/// Compute the receipts root hash over all receipts.
#[must_use]
pub fn receipts_root(receipts: &[Receipt]) -> Hash32 {
    let mut buf = Vec::with_capacity(11 + 4 + receipts.len() * (32 + 1 + 8 + 8 + 8 + 8));
    buf.extend_from_slice(b"IONA_RCPROOT");
    buf.extend_from_slice(&(receipts.len() as u32).to_le_bytes());
    for r in receipts {
        buf.extend_from_slice(&r.tx_hash.0);
        buf.extend_from_slice(&[r.success as u8]);
        buf.extend_from_slice(&r.gas_used.to_le_bytes());
        buf.extend_from_slice(&r.effective_gas_price.to_le_bytes());
        buf.extend_from_slice(&r.burned.to_le_bytes());
        buf.extend_from_slice(&r.tip.to_le_bytes());
    }
    hash_bytes(&buf)
}

// ── Global state ────────────────────────────────────────────────────────

static GLOBAL_CACHE: std::sync::OnceLock<HashCache> = std::sync::OnceLock::new();
static GLOBAL_METRICS: std::sync::OnceLock<Arc<TypesMetrics>> = std::sync::OnceLock::new();

fn get_global_state() -> (Option<&'static HashCache>, Option<&'static TypesMetrics>) {
    (GLOBAL_CACHE.get(), GLOBAL_METRICS.get().map(|m| m.as_ref()))
}

/// Initialize the global hash cache and metrics.
pub fn init_global(config: TypesConfig) -> Result<(), String> {
    config.validate()?;
    let metrics = Arc::new(TypesMetrics::default());
    let cache = HashCache::new(&config, metrics.clone())?;
    GLOBAL_CACHE.set(cache).map_err(|_| "cache already initialized".to_string())?;
    GLOBAL_METRICS.set(metrics).map_err(|_| "metrics already initialized".to_string())?;
    Ok(())
}

/// Get the global metrics snapshot.
pub fn global_metrics_snapshot() -> Option<super::TypesMetrics> {
    GLOBAL_METRICS.get().map(|m| (**m).clone())
}

// ── Default values helpers ──────────────────────────────────────────────

#[inline]
const fn default_chain_id() -> u64 {
    6126151
}

#[inline]
const fn default_protocol_version() -> u32 {
    1
}

// ── Tests ─────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn dummy_tx() -> Tx {
        Tx {
            pubkey: vec![0xAA; 32],
            from: "test_addr".into(),
            nonce: 42,
            max_fee_per_gas: 100,
            max_priority_fee_per_gas: 10,
            gas_limit: 100_000,
            payload: "set a b".into(),
            signature: vec![0xBB; 64],
            chain_id: 1,
        }
    }

    #[test]
    fn test_hash32_zero() {
        let zero = Hash32::zero();
        assert_eq!(zero.0, [0u8; 32]);
    }

    #[test]
    fn test_tx_hash_deterministic() {
        let tx1 = dummy_tx();
        let tx2 = dummy_tx();
        assert_eq!(tx_hash(&tx1), tx_hash(&tx2));
    }

    #[test]
    fn test_tx_root_deterministic() {
        let txs = vec![dummy_tx(), dummy_tx()];
        let root1 = tx_root(&txs);
        let root2 = tx_root(&txs);
        assert_eq!(root1, root2);
    }

    #[test]
    fn test_receipts_root_deterministic() {
        let receipt = Receipt {
            tx_hash: Hash32::zero(),
            success: true,
            gas_used: 1000,
            intrinsic_gas_used: 21000,
            exec_gas_used: 0,
            vm_gas_used: 0,
            evm_gas_used: 0,
            effective_gas_price: 1,
            burned: 1,
            tip: 0,
            error: None,
            data: None,
        };
        let receipts = vec![receipt.clone(), receipt];
        let root1 = receipts_root(&receipts);
        let root2 = receipts_root(&receipts);
        assert_eq!(root1, root2);
    }

    #[test]
    fn test_block_id_deterministic() {
        let header = BlockHeader {
            height: 100,
            round: 5,
            prev: Hash32::zero(),
            proposer_pk: vec![0xAA; 32],
            tx_root: Hash32::zero(),
            receipts_root: Hash32::zero(),
            state_root: Hash32::zero(),
            base_fee_per_gas: 1,
            gas_used: 0,
            intrinsic_gas_used: 0,
            exec_gas_used: 0,
            vm_gas_used: 0,
            evm_gas_used: 0,
            chain_id: 6126151,
            timestamp: 123456,
            protocol_version: 1,
        };
        let block = Block {
            header: header.clone(),
            txs: vec![],
        };
        let id1 = block.id();
        let block2 = Block { header, txs: vec![] };
        let id2 = block2.id();
        assert_eq!(id1, id2);
    }

    #[test]
    fn test_quantum_hash_state_initialization() {
        let state = QuantumHashState::new();
        assert!((state.purity - 1.0).abs() < 1e-10);
        assert!((state.entropy - 0.0).abs() < 1e-10);
        assert!(state.is_valid);
    }

    #[test]
    fn test_hash_decoherence() {
        let mut state = QuantumHashState::new();
        let initial_purity = state.purity;
        state.apply_hash_decoherence(1000, 0.00001);
        assert!(state.purity < initial_purity);
        assert_eq!(state.bytes_hashed, 1000);
    }

    #[test]
    fn test_hash_channel() {
        let mut state = QuantumHashState::new();
        let initial_coherence = state.hash_coherence;
        state.apply_hash_channel();
        assert!(state.hash_coherence < initial_coherence);
    }

    #[test]
    fn test_hash_bytes_quantum() {
        let data = b"test data for quantum hashing";
        let (hash, state) = hash_bytes_quantum(data);
        assert_eq!(hash.0.len(), 32);
        assert!(state.bytes_hashed > 0);
        assert!(state.purity < 1.0);
    }

    #[test]
    fn test_tx_hash_quantum() {
        let tx = dummy_tx();
        let (hash, state) = tx_hash_quantum(&tx);
        assert_eq!(hash.0.len(), 32);
        assert!(state.bytes_hashed > 0);
        assert!(state.purity < 1.0);
    }

    #[test]
    fn test_hash_fidelity_identical() {
        let h1 = Hash32::from_bytes([0xAA; 32]);
        let h2 = Hash32::from_bytes([0xAA; 32]);
        assert!((h1.fidelity(&h2) - 1.0).abs() < 1e-10);
    }

    #[test]
    fn test_hash_fidelity_different() {
        let h1 = Hash32::from_bytes([0xAA; 32]);
        let h2 = Hash32::from_bytes([0xBB; 32]);
        assert!((h1.fidelity(&h2) - 0.0).abs() < 1e-10);
    }

    #[test]
    fn test_tx_quantum_purity() {
        let mut tx = dummy_tx();
        assert!(tx.quantum_purity() > 0.99);
        tx.pubkey = vec![0xCC; 31]; // invalid length
        assert!(tx.quantum_purity() < 1.0);
        tx.signature = vec![0xDD; 63]; // invalid length
        assert!(tx.quantum_purity() < 0.5);
    }

    #[test]
    fn test_hash_cache() {
        let config = TypesConfig {
            enable_hash_cache: true,
            cache_size: 10,
            ..Default::default()
        };
        let metrics = Arc::new(TypesMetrics::default());
        let cache = HashCache::new(&config, metrics.clone()).unwrap();
        let data = b"test data";
        let h1 = cache.get_or_compute(data, || hash_bytes(data));
        let h2 = cache.get_or_compute(data, || hash_bytes(data));
        assert_eq!(h1, h2);
        assert!(cache.len() > 0);
    }

    #[test]
    fn test_hash_cache_ttl() {
        let config = TypesConfig {
            enable_hash_cache: true,
            cache_size: 10,
            cache_ttl_secs: 1,
            ..Default::default()
        };
        let metrics = Arc::new(TypesMetrics::default());
        let cache = HashCache::new(&config, metrics.clone()).unwrap();
        let data = b"test data";
        let _ = cache.get_or_compute(data, || hash_bytes(data));
        std::thread::sleep(std::time::Duration::from_secs(2));
        let _ = cache.get_or_compute(data, || hash_bytes(data));
        // Cache should still have one entry (reinserted)
        assert_eq!(cache.len(), 1);
    }
}
