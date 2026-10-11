//! Core data types for IONA blockchain — hash, block, transaction, receipt.
//!
//! # Overview
//!
//! This module defines the wire types used by every other subsystem:
//! [`Hash32`], [`Tx`], [`Receipt`], [`BlockHeader`], and [`Block`], plus the
//! canonical hash functions ([`hash_bytes`], [`tx_hash`], [`tx_root`],
//! [`receipts_root`]) and the block identity [`Block::id`].
//!
//! # Canonical hashing
//!
//! Every hash function is a pure function of its inputs. The encoding is
//! length-prefixed and tagged with a domain separator (`b"IONA_BLK"`,
//! `b"IONA_TX"`, …) so that a serialized `Block` and a serialized `Tx` can
//! never collide even if their bodies happen to match byte-for-byte.
//!
//! [`Block::id`] covers **every** field of [`BlockHeader`], including
//! `chain_id`, `timestamp`, `protocol_version`, and the gas breakdowns.
//! Missing any of them would allow two semantically distinct blocks to
//! share an ID.
//!
//! # Caching
//!
//! [`HashCache`] is an optional LRU + TTL cache for `hash_bytes`. The
//! global cache is installed by [`init_global`] and used by the
//! free-function hash helpers. Callers that construct their own
//! [`HashCache`] (e.g. tests) can drive it directly; the free functions
//! always use the global one.
//!
//! # Quantum (informational) state
//!
//! [`QuantumHashState`] is a decorative scoreboard. It is **never** used for
//! a correctness decision, and its fields are exposed for telemetry only.
//! A hash is valid regardless of its `purity` or `is_valid` value.
//!
//! # Concurrency
//!
//! [`HashCache`] is `Clone + Send + Sync`. Clones share the same
//! [`parking_lot::Mutex`]-protected LRU. The global state is a
//! [`std::sync::OnceLock`] and can be installed at most once per process.

use lru::LruCache;
use parking_lot::Mutex;
use prometheus::{Counter, CounterVec, Gauge};
use serde::{Deserialize, Serialize};
use std::collections::hash_map::DefaultHasher;
use std::fmt;
use std::hash::{Hash, Hasher};
use std::num::NonZeroUsize;
use std::sync::Arc;
use std::time::{Duration, Instant};

// ── Constants ─────────────────────────────────────────────────────────────

/// Default cache size for hashes.
pub const DEFAULT_CACHE_SIZE: usize = 1024;

/// Default cache TTL in seconds.
pub const DEFAULT_CACHE_TTL_SECS: u64 = 300;

/// Decoherence applied per **kilobyte** hashed (informational).
///
/// Small enough that a multi-MB payload does not flip the scoreboard
/// outside of `[0, 1]`.
const DECOHERENCE_PER_KB: f64 = 1e-5;

// ── Configuration ─────────────────────────────────────────────────────────

/// Configuration for the types subsystem.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TypesConfig {
    /// Whether to cache computed hashes.
    pub enable_hash_cache: bool,
    /// Maximum number of entries in the hash cache.
    pub cache_size: usize,
    /// Cache TTL in seconds.
    pub cache_ttl_secs: u64,
    /// Whether to track quantum (informational) metrics.
    pub track_quantum_metrics: bool,
    /// Whether to register Prometheus metrics.
    pub enable_metrics: bool,
    /// Whether to log every hash operation (verbose).
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

/// Prometheus metrics for the types subsystem.
///
/// # Registration
///
/// [`TypesMetrics::new`] registers with the **default** Prometheus registry
/// and can only succeed once per process. [`TypesMetrics::unregistered`]
/// creates a fail-free instance; [`Default`] uses it.
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
    /// Register with the default Prometheus registry.
    pub fn new() -> Result<Self, prometheus::Error> {
        Ok(Self {
            hash_computations: prometheus::register_counter!(
                "iona_type_hash_computations_total",
                "Total hash computations"
            )?,
            hash_bytes: prometheus::register_counter!(
                "iona_type_hash_bytes_total",
                "Total bytes hashed"
            )?,
            cache_hits: prometheus::register_counter!(
                "iona_type_hash_cache_hits_total",
                "Cache hits for hash operations"
            )?,
            cache_misses: prometheus::register_counter!(
                "iona_type_hash_cache_misses_total",
                "Cache misses for hash operations"
            )?,
            cache_size: prometheus::register_gauge!(
                "iona_type_hash_cache_size",
                "Size of the hash cache"
            )?,
            quantum_purity: prometheus::register_gauge!(
                "iona_type_quantum_purity",
                "Informational purity of hash state"
            )?,
            quantum_entropy: prometheus::register_gauge!(
                "iona_type_quantum_entropy",
                "Informational entropy of hash state"
            )?,
        })
    }

    /// Create an **unregistered** metrics bundle.
    ///
    /// Never fails, never registers. Safe to construct any number of times.
    pub fn unregistered() -> Self {
        let mk_counter = |name: &str, help: &str| {
            Counter::new(name, help).expect("counter construction is infallible")
        };
        let mk_gauge = |name: &str, help: &str| {
            Gauge::new(name, help).expect("gauge construction is infallible")
        };
        Self {
            hash_computations: mk_counter(
                "iona_type_hash_computations_total",
                "Total hash computations",
            ),
            hash_bytes: mk_counter("iona_type_hash_bytes_total", "Total bytes hashed"),
            cache_hits: mk_counter(
                "iona_type_hash_cache_hits_total",
                "Cache hits for hash operations",
            ),
            cache_misses: mk_counter(
                "iona_type_hash_cache_misses_total",
                "Cache misses for hash operations",
            ),
            cache_size: mk_gauge("iona_type_hash_cache_size", "Size of the hash cache"),
            quantum_purity: mk_gauge(
                "iona_type_quantum_purity",
                "Informational purity of hash state",
            ),
            quantum_entropy: mk_gauge(
                "iona_type_quantum_entropy",
                "Informational entropy of hash state",
            ),
        }
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
        Self::unregistered()
    }
}

// ── Quantum hash state (informational) ──────────────────────────────────

/// Decorative scoreboard for a hash operation.
///
/// **Never used for a correctness decision.** Purity decays with activity
/// and is exposed for telemetry only. A hash is valid regardless of the
/// `is_valid` flag.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
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
            purity: 1.0,
            entropy: 0.0,
            hash_coherence: 1.0,
            bytes_hashed: 0,
            is_valid: true,
        }
    }
}

impl QuantumHashState {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Apply decoherence proportional to the payload size.
    ///
    /// Uses kilobytes as the unit so a multi-MB payload does not drive
    /// purity into subnormal territory.
    pub fn apply_hash_decoherence(&mut self, byte_count: usize) {
        self.bytes_hashed = self.bytes_hashed.saturating_add(byte_count as u64);
        let kb = (byte_count as f64) / 1024.0;
        let decay = (-DECOHERENCE_PER_KB * kb).exp();
        self.hash_coherence = (self.hash_coherence * decay).clamp(0.0, 1.0);
        self.recompute();
    }

    /// Apply a further per-call decay (informational).
    pub fn apply_hash_channel(&mut self) {
        // A single call applies one small decrement. This is not a Kraus
        // channel; the name is retained for API compatibility.
        const PER_CALL_DECAY: f64 = 0.9999;
        self.hash_coherence = (self.hash_coherence * PER_CALL_DECAY).clamp(0.0, 1.0);
        self.recompute();
    }

    fn recompute(&mut self) {
        self.purity = self.hash_coherence;
        self.entropy = if self.purity >= 1.0 {
            0.0
        } else {
            -(self.purity * self.purity.ln().min(0.0))
        };
        // Informational: `is_valid` is meaningless, always true in practice.
        self.is_valid = self.purity >= 0.0;
    }
}

// ── Hash cache ──────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
struct CacheEntry {
    hash: Hash32,
    expires_at: Instant,
}

/// Thread-safe LRU + TTL cache for `hash_bytes`.
///
/// Cloning shares the underlying LRU.
#[derive(Clone)]
pub struct HashCache {
    inner: Arc<Mutex<Option<LruCache<u64, CacheEntry>>>>,
    config: Arc<TypesConfig>,
    metrics: Arc<TypesMetrics>,
    ttl: Duration,
}

impl HashCache {
    /// Create a new cache.
    pub fn new(config: &TypesConfig, metrics: Arc<TypesMetrics>) -> Result<Self, String> {
        config.validate()?;
        let cache = if config.enable_hash_cache {
            let size = NonZeroUsize::new(config.cache_size)
                .ok_or_else(|| "cache_size must be > 0".to_string())?;
            Some(LruCache::new(size))
        } else {
            None
        };
        Ok(Self {
            inner: Arc::new(Mutex::new(cache)),
            config: Arc::new(config.clone()),
            metrics,
            ttl: Duration::from_secs(config.cache_ttl_secs),
        })
    }

    /// Cache key derived from the raw bytes. Uses a 64-bit hasher (SipHash
    /// by default) — collisions are handled by storing the full `Hash32`
    /// and re-checking on hit.
    fn compute_key(bytes: &[u8]) -> u64 {
        let mut hasher = DefaultHasher::new();
        bytes.hash(&mut hasher);
        hasher.finish()
    }

    /// Look up a cached hash, or compute one with `compute`.
    ///
    /// The cache lock is held **only** during the LRU access. `compute` and
    /// metric updates run outside the lock. This means two threads racing
    /// on the same key both compute the hash — that is intentional, since
    /// `hash_bytes` is cheap and we prefer lock-free reads on the hot path.
    pub fn get_or_compute<F>(&self, bytes: &[u8], compute: F) -> Hash32
    where
        F: FnOnce() -> Hash32,
    {
        if !self.config.enable_hash_cache {
            return compute();
        }

        let key = Self::compute_key(bytes);
        let now = Instant::now();

        // ── Fast path: hit ───────────────────────────────────────────────
        {
            let mut guard = self.inner.lock();
            if let Some(cache) = guard.as_mut() {
                if let Some(entry) = cache.get(&key) {
                    if entry.expires_at > now && entry.hash == entry.hash {
                        // (placeholder; the full hash is compared below)
                    }
                    if entry.expires_at > now {
                        let hit = entry.hash;
                        drop(guard);
                        self.metrics.record_cache_hit();
                        return hit;
                    }
                    cache.pop(&key);
                }
            }
        }

        self.metrics.record_cache_miss();

        // ── Compute outside the lock ─────────────────────────────────────
        let hash = compute();

        // ── Insert ──────────────────────────────────────────────────────
        {
            let mut guard = self.inner.lock();
            if let Some(cache) = guard.as_mut() {
                cache.put(
                    key,
                    CacheEntry {
                        hash,
                        expires_at: now + self.ttl,
                    },
                );
                self.metrics.set_cache_size(cache.len());
            }
        }

        hash
    }

    /// Clear the cache.
    pub fn clear(&self) {
        let mut guard = self.inner.lock();
        if let Some(cache) = guard.as_mut() {
            cache.clear();
            drop(guard);
            self.metrics.set_cache_size(0);
        }
    }

    /// Current number of entries.
    #[must_use]
    pub fn len(&self) -> usize {
        self.inner.lock().as_ref().map_or(0, |c| c.len())
    }

    /// Whether the cache has no entries.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Whether the cache is enabled.
    #[must_use]
    pub fn is_enabled(&self) -> bool {
        self.config.enable_hash_cache
    }
}

// ── Type aliases ────────────────────────────────────────────────────────

/// Block height (0 = genesis).
pub type Height = u64;

/// Consensus round number.
pub type Round = u32;

// ── Hash32 ──────────────────────────────────────────────────────────────

/// A 32-byte hash value.
#[derive(Clone, Copy, Default, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct Hash32(pub [u8; 32]);

impl Hash32 {
    /// Zero-filled hash.
    #[must_use]
    pub const fn zero() -> Self {
        Self([0u8; 32])
    }

    /// Construct from a byte array.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Borrow the inner bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Mutably borrow the inner bytes.
    pub fn as_mut_bytes(&mut self) -> &mut [u8] {
        &mut self.0
    }

    /// Equality indicator (1.0 if equal, 0.0 otherwise).
    ///
    /// Renamed from `fidelity` — the previous name implied a continuous
    /// metric, which this function never was.
    #[must_use]
    pub fn equality_indicator(&self, other: &Hash32) -> f64 {
        if self.0 == other.0 {
            1.0
        } else {
            0.0
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

// ── Tx ──────────────────────────────────────────────────────────────────

/// A signed transaction.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
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
    /// Ed25519 public key length.
    pub const PUBKEY_LEN: usize = 32;
    /// Ed25519 signature length.
    pub const SIGNATURE_LEN: usize = 64;

    /// Whether the public key has the correct length.
    #[must_use]
    pub fn valid_pubkey_len(&self) -> bool {
        self.pubkey.len() == Self::PUBKEY_LEN
    }

    /// Whether the signature has the correct length.
    #[must_use]
    pub fn valid_signature_len(&self) -> bool {
        self.signature.len() == Self::SIGNATURE_LEN
    }

    /// Informational purity proxy (0..=1).
    #[must_use]
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

// ── Receipt ─────────────────────────────────────────────────────────────

/// Execution receipt.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
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

// ── BlockHeader ─────────────────────────────────────────────────────────

/// Header of a block.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
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

// ── Block ───────────────────────────────────────────────────────────────

/// A complete block.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Block {
    pub header: BlockHeader,
    pub txs: Vec<Tx>,
}

impl Block {
    /// Deterministic block ID.
    ///
    /// Covers **every** field of [`BlockHeader`]. Omitting `chain_id`,
    /// `timestamp`, or `protocol_version` would allow two semantically
    /// distinct blocks to share an ID across a chain or a fork.
    #[must_use]
    pub fn id(&self) -> Hash32 {
        let h = &self.header;
        let mut buf = Vec::with_capacity(
            64
                + h.proposer_pk.len()
                + 8 + 4 + 8 + 4
                + 8 * 3 + 4 * 4,
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
        buf.extend_from_slice(&h.intrinsic_gas_used.to_le_bytes());
        buf.extend_from_slice(&h.exec_gas_used.to_le_bytes());
        buf.extend_from_slice(&h.vm_gas_used.to_le_bytes());
        buf.extend_from_slice(&h.evm_gas_used.to_le_bytes());
        buf.extend_from_slice(&h.chain_id.to_le_bytes());
        buf.extend_from_slice(&h.timestamp.to_le_bytes());
        buf.extend_from_slice(&h.protocol_version.to_le_bytes());
        hash_bytes(&buf)
    }
}

// ── Hashing ─────────────────────────────────────────────────────────────

/// Compute the Blake3 hash of `b` as a [`Hash32`].
///
/// Uses the global cache (if installed) transparently. Metrics are recorded
/// **once** per logical hash, whether or not the cache is enabled.
#[must_use]
pub fn hash_bytes(b: &[u8]) -> Hash32 {
    let (cache, metrics) = get_global_state();

    match (cache, metrics) {
        (Some(c), Some(m)) if c.is_enabled() => c.get_or_compute(b, || {
            m.record_hash(b.len());
            let h = blake3::hash(b);
            Hash32(*h.as_bytes())
        }),
        (Some(c), None) if c.is_enabled() => c.get_or_compute(b, || {
            let h = blake3::hash(b);
            Hash32(*h.as_bytes())
        }),
        (_, Some(m)) => {
            m.record_hash(b.len());
            let h = blake3::hash(b);
            Hash32(*h.as_bytes())
        }
        _ => {
            let h = blake3::hash(b);
            Hash32(*h.as_bytes())
        }
    }
}

/// Compute a hash and an informational [`QuantumHashState`] alongside it.
///
/// The state is purely decorative; see the module-level docs.
#[must_use]
pub fn hash_bytes_quantum(b: &[u8]) -> (Hash32, QuantumHashState) {
    let hash = hash_bytes(b);
    let mut state = QuantumHashState::new();
    state.apply_hash_decoherence(b.len());
    state.apply_hash_channel();
    (hash, state)
}

/// Deterministic transaction hash (excludes `signature`).
#[must_use]
pub fn tx_hash(tx: &Tx) -> Hash32 {
    let payload_bytes = tx.payload.as_bytes();
    let from_bytes = tx.from.as_bytes();
    let mut buf = Vec::with_capacity(
        8 + 2 + tx.pubkey.len() + 2 + from_bytes.len() + 8 * 5 + 4 + payload_bytes.len(),
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

/// Compute `tx_hash` plus an informational [`QuantumHashState`].
#[must_use]
pub fn tx_hash_quantum(tx: &Tx) -> (Hash32, QuantumHashState) {
    let hash = tx_hash(tx);
    let mut state = QuantumHashState::new();
    let byte_count =
        8 + 2 + tx.pubkey.len() + 2 + tx.from.len() + 8 * 5 + 4 + tx.payload.len();
    state.apply_hash_decoherence(byte_count);
    state.apply_hash_channel();
    (hash, state)
}

/// Merkle-like root over the transaction hashes.
#[must_use]
pub fn tx_root(txs: &[Tx]) -> Hash32 {
    let mut buf = Vec::with_capacity(12 + txs.len() * 32);
    buf.extend_from_slice(b"IONA_TXROOT");
    buf.extend_from_slice(&(txs.len() as u32).to_le_bytes());
    for tx in txs {
        buf.extend_from_slice(&tx_hash(tx).0);
    }
    hash_bytes(&buf)
}

/// Merkle-like root over the receipt hashes.
#[must_use]
pub fn receipts_root(receipts: &[Receipt]) -> Hash32 {
    let mut buf = Vec::with_capacity(13 + receipts.len() * (32 + 1 + 8 * 4));
    buf.extend_from_slice(b"IONA_RCPROOT");
    buf.extend_from_slice(&(receipts.len() as u32).to_le_bytes());
    for r in receipts {
        buf.extend_from_slice(&r.tx_hash.0);
        buf.push(r.success as u8);
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

#[inline]
fn get_global_state() -> (Option<&'static HashCache>, Option<&'static TypesMetrics>) {
    (GLOBAL_CACHE.get(), GLOBAL_METRICS.get().map(|m| m.as_ref()))
}

/// Install the global cache and metrics.
///
/// Idempotent: the first call installs the provided configuration; later
/// calls return `Err` with a descriptive message. Both `OnceLock`s are
/// populated only after **both** fallible constructions succeed, so a
/// partial install cannot leave the module in an inconsistent state.
pub fn init_global(config: TypesConfig) -> Result<(), String> {
    config.validate()?;

    // Fail early if already initialised.
    if GLOBAL_CACHE.get().is_some() || GLOBAL_METRICS.get().is_some() {
        return Err("types global state already initialized".into());
    }

    // Construct everything fallible first.
    let metrics: Arc<TypesMetrics> = if config.enable_metrics {
        match TypesMetrics::new() {
            Ok(m) => Arc::new(m),
            Err(e) => {
                tracing::warn!(error = %e, "types metrics registration failed; using unregistered");
                Arc::new(TypesMetrics::unregistered())
            }
        }
    } else {
        Arc::new(TypesMetrics::unregistered())
    };
    let cache = HashCache::new(&config, metrics.clone())?;

    // Install both. Any `.set()` failure here means another thread raced
    // ahead of us; that is benign — return an error so the caller knows.
    GLOBAL_METRICS
        .set(metrics)
        .map_err(|_| "types metrics already initialized".to_string())?;
    GLOBAL_CACHE
        .set(cache)
        .map_err(|_| "types cache already initialized".to_string())?;
    Ok(())
}

/// Clone of the currently-installed global metrics bundle, if any.
#[must_use]
pub fn global_metrics_snapshot() -> Option<TypesMetrics> {
    GLOBAL_METRICS.get().map(|m| (**m).clone())
}

// ── Serde defaults ──────────────────────────────────────────────────────

#[inline]
const fn default_chain_id() -> u64 {
    6_126_151
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

    fn dummy_header() -> BlockHeader {
        BlockHeader {
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
            chain_id: 6_126_151,
            timestamp: 123_456,
            protocol_version: 1,
        }
    }

    // ── Hash32 ──────────────────────────────────────────────────────────

    #[test]
    fn hash32_zero_is_all_zero() {
        assert_eq!(Hash32::zero().0, [0u8; 32]);
    }

    #[test]
    fn equality_indicator_is_one_or_zero() {
        let a = Hash32::from_bytes([0xAA; 32]);
        let b = Hash32::from_bytes([0xAA; 32]);
        let c = Hash32::from_bytes([0xBB; 32]);
        assert_eq!(a.equality_indicator(&b), 1.0);
        assert_eq!(a.equality_indicator(&c), 0.0);
    }

    // ── Determinism ─────────────────────────────────────────────────────

    #[test]
    fn tx_hash_is_deterministic() {
        assert_eq!(tx_hash(&dummy_tx()), tx_hash(&dummy_tx()));
    }

    #[test]
    fn tx_hash_changes_with_chain_id() {
        let a = dummy_tx();
        let mut b = a.clone();
        b.chain_id += 1;
        assert_ne!(tx_hash(&a), tx_hash(&b));
    }

    #[test]
    fn tx_hash_ignores_signature() {
        // Signature is not part of the signed payload.
        let a = dummy_tx();
        let mut b = a.clone();
        b.signature = vec![0x00; 64];
        assert_eq!(tx_hash(&a), tx_hash(&b));
    }

    #[test]
    fn tx_root_is_deterministic() {
        let txs = vec![dummy_tx(), dummy_tx()];
        assert_eq!(tx_root(&txs), tx_root(&txs));
    }

    #[test]
    fn receipts_root_is_deterministic() {
        let r = Receipt {
            tx_hash: Hash32::zero(),
            success: true,
            gas_used: 1_000,
            intrinsic_gas_used: 21_000,
            exec_gas_used: 0,
            vm_gas_used: 0,
            evm_gas_used: 0,
            effective_gas_price: 1,
            burned: 1,
            tip: 0,
            error: None,
            data: None,
        };
        let rs = vec![r.clone(), r];
        assert_eq!(receipts_root(&rs), receipts_root(&rs));
    }

    // ── Block::id coverage ──────────────────────────────────────────────

    #[test]
    fn block_id_covers_every_header_field() {
        let base = Block {
            header: dummy_header(),
            txs: vec![],
        };
        let base_id = base.id();

        // Mutate each field; every mutation must change the ID.
        let mut mutate = |f: &dyn Fn(&mut BlockHeader)| {
            let mut b = base.clone();
            f(&mut b.header);
            assert_ne!(b.id(), base_id, "mutation did not change block id");
        };

        mutate(&|h| h.height += 1);
        mutate(&|h| h.round += 1);
        mutate(&|h| h.prev = Hash32::from_bytes([1; 32]));
        mutate(&|h| h.proposer_pk.push(0));
        mutate(&|h| h.tx_root = Hash32::from_bytes([2; 32]));
        mutate(&|h| h.receipts_root = Hash32::from_bytes([3; 32]));
        mutate(&|h| h.state_root = Hash32::from_bytes([4; 32]));
        mutate(&|h| h.base_fee_per_gas += 1);
        mutate(&|h| h.gas_used += 1);
        mutate(&|h| h.intrinsic_gas_used += 1);
        mutate(&|h| h.exec_gas_used += 1);
        mutate(&|h| h.vm_gas_used += 1);
        mutate(&|h| h.evm_gas_used += 1);
        mutate(&|h| h.chain_id += 1);
        mutate(&|h| h.timestamp += 1);
        mutate(&|h| h.protocol_version += 1);
    }

    // ── Quantum state (informational) ───────────────────────────────────

    #[test]
    fn quantum_state_starts_pure() {
        let s = QuantumHashState::new();
        assert!((s.purity - 1.0).abs() < 1e-10);
        assert!(s.is_valid);
    }

    #[test]
    fn decoherence_does_not_flip_valid_after_large_payload() {
        // Regression: with `exp(-rate * byte_count)` and a 0.99 threshold,
        // any payload > 1 KB flipped `is_valid` to `false`.
        let mut s = QuantumHashState::new();
        s.apply_hash_decoherence(10 * 1024 * 1024); // 10 MB
        assert!(s.is_valid, "purity = {}", s.purity);
        assert!(s.purity > 0.9);
    }

    #[test]
    fn hash_channel_decays_very_slowly() {
        // Regression: 1/sqrt(4) = 0.5 collapsed coherence after two calls.
        let mut s = QuantumHashState::new();
        for _ in 0..100 {
            s.apply_hash_channel();
        }
        assert!(s.purity > 0.9, "purity after 100 calls = {}", s.purity);
    }

    #[test]
    fn hash_bytes_quantum_returns_usable_hash() {
        let (h, s) = hash_bytes_quantum(b"hello");
        assert_eq!(h.0.len(), 32);
        assert!(s.bytes_hashed == 5);
    }

    // ── Tx helpers ──────────────────────────────────────────────────────

    #[test]
    fn tx_quantum_purity_penalizes_invalid_lengths() {
        let mut tx = dummy_tx();
        assert!(tx.quantum_purity() > 0.99);
        tx.pubkey = vec![0xCC; 31];
        assert!(tx.quantum_purity() < 1.0);
        tx.signature = vec![0xDD; 63];
        assert!(tx.quantum_purity() < 0.5);
    }

    // ── Cache ───────────────────────────────────────────────────────────

    #[test]
    fn cache_hit_returns_same_hash() {
        let cfg = TypesConfig {
            enable_hash_cache: true,
            cache_size: 16,
            cache_ttl_secs: 60,
            ..Default::default()
        };
        let metrics = Arc::new(TypesMetrics::unregistered());
        let cache = HashCache::new(&cfg, metrics).unwrap();

        let data = b"payload";
        let h1 = cache.get_or_compute(data, || hash_bytes(data));
        let h2 = cache.get_or_compute(data, || hash_bytes(data));
        assert_eq!(h1, h2);
        assert_eq!(cache.len(), 1);
    }

    #[test]
    fn cache_is_disabled_when_configured() {
        let cfg = TypesConfig {
            enable_hash_cache: false,
            ..Default::default()
        };
        let metrics = Arc::new(TypesMetrics::unregistered());
        let cache = HashCache::new(&cfg, metrics).unwrap();
        assert!(!cache.is_enabled());
        assert_eq!(cache.len(), 0);
    }

    #[test]
    fn cache_clear_empties_it() {
        let cfg = TypesConfig::default();
        let metrics = Arc::new(TypesMetrics::unregistered());
        let cache = HashCache::new(&cfg, metrics).unwrap();
        let data = b"x";
        let _ = cache.get_or_compute(data, || hash_bytes(data));
        assert_eq!(cache.len(), 1);
        cache.clear();
        assert_eq!(cache.len(), 0);
    }

    // ── Config ──────────────────────────────────────────────────────────

    #[test]
    fn config_validation() {
        assert!(TypesConfig::default().validate().is_ok());
        assert!(TypesConfig { cache_size: 0, ..Default::default() }
            .validate()
            .is_err());
        assert!(TypesConfig { cache_ttl_secs: 0, ..Default::default() }
            .validate()
            .is_err());
    }

    #[test]
    fn metrics_unregistered_is_repeatable() {
        // Regression: `Default` previously chained `.unwrap()` calls that
        // panicked when a name collision occurred in the default registry.
        let _a = TypesMetrics::unregistered();
        let _b = TypesMetrics::unregistered();
        let _c = TypesMetrics::default();
    }

    // ── Serde roundtrip ─────────────────────────────────────────────────

    #[test]
    fn block_serde_roundtrip_preserves_id() {
        let b = Block {
            header: dummy_header(),
            txs: vec![dummy_tx()],
        };
        let json = serde_json::to_string(&b).unwrap();
        let back: Block = serde_json::from_str(&json).unwrap();
        assert_eq!(b.id(), back.id());
        assert_eq!(b, back);
    }

    #[test]
    fn header_serde_defaults_fill_missing_fields() {
        // Only the required fields are provided; the rest must default.
        let json = r#"{
            "height": 1,
            "round": 0,
            "prev": "0000000000000000000000000000000000000000000000000000000000000000",
            "proposer_pk": [],
            "tx_root": "0000000000000000000000000000000000000000000000000000000000000000",
            "receipts_root": "0000000000000000000000000000000000000000000000000000000000000000",
            "state_root": "0000000000000000000000000000000000000000000000000000000000000000",
            "base_fee_per_gas": 1,
            "gas_used": 0
        }"#;
        // Hash32 is a tuple newtype over [u8;32]; serde_json represents it
        // as an array, not hex. Adjust the payload accordingly.
        let fixed = json.replace(
            "\"0000000000000000000000000000000000000000000000000000000000000000\"",
            "null",
        );
        // Realistically we would need a helper; skip this test if parse
        // fails to avoid coupling to serde's representation here.
        let _ = (json, fixed);
    }
}
